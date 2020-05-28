"""Platform for xmpp integration."""
import asyncio
from collections import deque
from datetime import datetime
import logging
import os

from omemo.exceptions import MissingBundleException
from slixmpp import JID, ClientXMPP
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.stanza import Message
import slixmpp_omemo
from slixmpp_omemo import (
    EncryptionPrepareException,
    MissingOwnKey,
    NoAvailableSession,
    UndecidedException,
    UntrustedException,
)
import voluptuous as vol

from homeassistant.components.notify import PLATFORM_SCHEMA
from homeassistant.const import (
    CONF_NAME,
    CONF_PASSWORD,
    CONF_RECIPIENT,
    CONF_RESOURCE,
    CONF_ROOM,
    CONF_SENDER,
)
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import Entity

_LOGGER = logging.getLogger(__name__)

CONF_TLS = "tls"
CONF_VERIFY = "verify"
DEFAULT_RESOURCE = "home-assistant"
CONF_HOLD_MESSAGE = "message-cache-limit"
CONF_TEMP_DIR = "omemo-dir"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_SENDER): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Optional(CONF_RESOURCE, default=DEFAULT_RESOURCE): cv.string,
        vol.Optional(CONF_ROOM, default=""): cv.string,
        vol.Optional(CONF_TLS, default=True): cv.boolean,
        vol.Optional(CONF_VERIFY, default=True): cv.boolean,
        vol.Optional(CONF_HOLD_MESSAGE, default=0): cv.positive_int,
        vol.Optional(CONF_NAME, default="xmpp"): cv.string,
        vol.Optional(CONF_TEMP_DIR, default="/tmp/xmpp"): cv.string,
    }
)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the xmpp platform."""

    async_add_entities(
        [
            XmppSensor(
                config.get(CONF_SENDER),
                config.get(CONF_RESOURCE),
                config.get(CONF_PASSWORD),
                config.get(CONF_RECIPIENT),
                config.get(CONF_TLS),
                config.get(CONF_VERIFY),
                config.get(CONF_ROOM),
                config.get(CONF_HOLD_MESSAGE),
                hass,
                config,
            )
        ]
    )


class XmppSensor(Entity):
    """Representation of a sensor."""

    def __init__(
        self,
        sender,
        resource,
        password,
        recipient,
        tls,
        verify,
        room,
        last_message,
        hass,
        config,
    ):
        """Initialize the sensor."""
        self._state = None
        self._hass = hass
        self._sender = sender
        self._resource = resource
        self._password = password
        self._recipient = recipient
        self._tls = tls
        self._verify = verify
        self._room = room
        self._hold_message = last_message

        self._client = Xmpp(
            sender,
            password,
            tls,
            hass,
            config,
            room=room,
            last_message=last_message,
            verify_certificate=verify,
        )

    @property
    def name(self):
        """Return the name of the xmpp service."""
        return "XMPP Message Receiver"

    @property
    def state(self):
        """Return the state of the xmpp service."""
        return self._state

    async def async_update(self):
        """Fetch new state data for the sensor."""
        self._state = {"attributes": {"messages": self._client.messages}}
        self._client_message.clear()
        _LOGGER.debug(f"state: {self._state}")


class Xmpp(ClientXMPP):
    """Represents the xmpp client."""

    def __init__(
        self,
        sender,
        password,
        use_tls,
        hass,
        config,
        room=False,
        last_message=0,
        verify_certificate=False,
    ):
        """Initialize xmpp client."""
        super().__init__(sender, password)

        _LOGGER.debug("Initialize")

        self.loop = hass.loop
        self.hass = hass
        self.config = config

        self.eme_ns = "eu.siacs.conversations.axolotl"

        os.makedirs(self.config.get(CONF_TEMP_DIR), exist_ok=True)

        self.register_plugin("xep_0030")
        self.register_plugin("xep_0199")
        self.register_plugin("xep_0380")
        self.register_plugin(
            "xep_0384",
            {"data_dir": self.config.get(CONF_TEMP_DIR)},
            module=slixmpp_omemo,
        )

        self.force_starttls = use_tls
        self.use_ipv6 = False
        self.add_event_handler("failed_auth", self.disconnect_on_login_fail)
        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("message", self.message_handler)
        self.add_event_handler("message_encryption", self.encrypted_message_handler)

        _LOGGER.debug("message event added.")

        self._hold_message = last_message
        self._messages = deque(maxlen=last_message)

        if room:
            self.register_plugin("xep_0045")  # MUC
        if not verify_certificate:
            self.add_event_handler("ssl_invalid_cert", self.discard_ssl_invalid_cert)

        self.connect(force_starttls=self.force_starttls, use_ssl=False)
        _LOGGER.debug("connected")

    @property
    def messages(self):
        """Return the latest messages."""
        return self._messages

    async def session_start(self, event):
        """Handle start of the session."""
        _LOGGER.debug("session start.")
        self.send_presence()

    async def message_handler(self, msg: Message) -> None:
        """Handle when message received."""
        asyncio.ensure_future(self.message(msg))

    async def encrypted_message_handler(self, msg) -> None:
        """Handle when encrypted message received."""
        asyncio.ensure_future(self.message(msg))

    async def message(self, msg: Message, allow_untrusted: bool = False) -> None:
        """Process incoming message stanzas."""

        if msg["type"] not in ("chat", "normal"):
            return None

        if not self["xep_0384"].is_encrypted(msg):
            await self.plain_reply(
                msg, "This message was not encrypted.\n%(body)s" % msg
            )
            return None

        try:
            mfrom = msg["from"]
            encrypted = msg["omemo_encrypted"]
            body = self["xep_0384"].decrypt_message(encrypted, mfrom, allow_untrusted)
            self._messages.append(
                {"from": mfrom, "message": body, "timestamp": datetime.now()}
            )
            await self.encrypted_reply(msg, "Thanks for sending")
            return None
        except (MissingOwnKey,):
            # The message is missing our own key, it was not encrypted for
            # us, and we can't decrypt it.
            await self.plain_reply(
                msg, "I can't decrypt this message as it is not encrypted for me.",
            )
            return None
        except (NoAvailableSession,):
            # We received a message from that contained a session that we
            # don't know about (deleted session storage, etc.). We can't
            # decrypt the message, and it's going to be lost.
            # Here, as we need to initiate a new encrypted session, it is
            # best if we send an encrypted message directly. XXX: Is it
            # where we talk about self-healing messages?
            await self.encrypted_reply(
                msg,
                "I can't decrypt this message as it uses an encrypted "
                "session I don't know about.",
            )
            return None
        except (UndecidedException, UntrustedException) as exn:
            # We received a message from an untrusted device. We can
            # choose to decrypt the message nonetheless, with the
            # `allow_untrusted` flag on the `decrypt_message` call, which
            # we will do here. This is only possible for decryption,
            # encryption will require us to decide if we trust the device
            # or not. Clients _should_ indicate that the message was not
            # trusted, or in undecided state, if they decide to decrypt it
            # anyway.
            await self.plain_reply(
                msg, "Your device '%s' is not in my trusted devices." % exn.device,
            )
            # We resend, setting the `allow_untrusted` parameter to True.
            await self.message(msg, allow_untrusted=True)
            return None
        except (EncryptionPrepareException,):
            # Slixmpp tried its best, but there were errors it couldn't
            # resolve. At this point you should have seen other exceptions
            # and given a chance to resolve them already.
            await self.plain_reply(msg, "I was not able to decrypt the message.")
            return None
        except (Exception,) as exn:
            await self.plain_reply(
                msg, "An error occurred while attempting decryption.\n%r" % exn
            )
            raise

        return None

    async def disconnect_on_login_fail(self, event):
        """Disconnect from the server if credentials are invalid."""
        _LOGGER.warning("Login failed")
        self.disconnect()

    @staticmethod
    def discard_ssl_invalid_cert(event):
        """Do nothing if ssl certificate is invalid."""
        _LOGGER.info("Ignoring invalid SSL certificate as requested")

    async def plain_reply(self, original_msg, body):
        """Reply to plain messages."""

        mto = original_msg["from"]
        mtype = original_msg["type"]
        msg = self.make_message(mto=mto, mtype=mtype)
        msg["body"] = body
        return msg.send()

    async def encrypted_reply(self, original_msg, body):
        """Reply to encrypted messages."""

        mto = original_msg["from"]
        mtype = original_msg["type"]
        msg = self.make_message(mto=mto, mtype=mtype)
        msg["eme"]["namespace"] = self.eme_ns
        msg["eme"]["name"] = self["xep_0380"].mechanisms[self.eme_ns]

        expect_problems = {}

        while True:
            try:
                # `encrypt_message` excepts the plaintext to be sent, a list of
                # bare JIDs to encrypt to, and optionally a dict of problems to
                # expect per bare JID.
                #
                # Note that this function returns an `<encrypted/>` object,
                # and not a full Message stanza. This combined with the
                # `recipients` parameter that requires for a list of JIDs,
                # allows you to encrypt for 1:1 as well as groupchats (MUC).
                #
                # `expect_problems`: See EncryptionPrepareException handling.
                recipients = [mto]
                encrypt = await self["xep_0384"].encrypt_message(
                    body, recipients, expect_problems
                )
                msg.append(encrypt)
                return msg.send()
            except UndecidedException as exn:
                # The library prevents us from sending a message to an
                # untrusted/undecided barejid, so we need to make a decision here.
                # This is where you prompt your user to ask what to do. In
                # this bot we will automatically trust undecided recipients.
                self["xep_0384"].trust(exn.bare_jid, exn.device, exn.ik)
            # TODO: catch NoEligibleDevicesException
            except EncryptionPrepareException as exn:
                # This exception is being raised when the library has tried
                # all it could and doesn't know what to do anymore. It
                # contains a list of exceptions that the user must resolve, or
                # explicitly ignore via `expect_problems`.
                # TODO: We might need to bail out here if errors are the same?
                for error in exn.errors:
                    if isinstance(error, MissingBundleException):
                        # We choose to ignore MissingBundleException. It seems
                        # to be somewhat accepted that it's better not to
                        # encrypt for a device if it has problems and encrypt
                        # for the rest, rather than error out. The "faulty"
                        # device won't be able to decrypt and should display a
                        # generic message. The receiving end-user at this
                        # point can bring up the issue if it happens.
                        self.plain_reply(
                            original_msg,
                            'Could not find keys for device "%d" of recipient "%s". Skipping.'
                            % (error.device, error.bare_jid),
                        )
                        jid = JID(error.bare_jid)
                        device_list = expect_problems.setdefault(jid, [])
                        device_list.append(error.device)
            except (IqError, IqTimeout) as exn:
                self.plain_reply(
                    original_msg,
                    "An error occurred while fetching information on a recipient.\n%r"
                    % exn,
                )
                return None
            except Exception as exn:
                await self.plain_reply(
                    original_msg,
                    "An error occurred while attempting to encrypt.\n%r" % exn,
                )
                raise

        return None
