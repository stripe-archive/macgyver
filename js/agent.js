/*
 * ssh-agent over postMessage
 *
 * Implements the ssh-agent binary protocol
 * (http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent?rev=HEAD),
 * where Ports correspond to sockets, and individual messages are byte arrays
 * *without* the length header.
 *
 * For reference, here is a breakdown of how to encode the relevant types (all
 * numeric types are network-endian):
 *
 *  - string: uint32 length + data with no trailing NULL
 *    reference: https://tools.ietf.org/html/rfc4251#page-9
 *
 *  - mpint: uint32 length + 2's complement data (with prefixed 0 to
 *    disambiguate positive numbers)
 *    reference: https://tools.ietf.org/html/rfc4251#page-9
 *
 *  - key blob: string "ssh-rsa" + mpint e + mpint n
 *    reference: https://tools.ietf.org/html/rfc4253#page-15
 *
 *  - signature: string "ssh-rsa" + mpint s (I think)
 *    reference: https://tools.ietf.org/html/rfc4253#page-15
 */

// This extension's API allows signing arbitrary data. Make sure it's only
// exposed to extensions that are allowed that power
var ALLOWED_CLIENTS = new Set([
  // Secure Shell
  "pnhechapfaindjhompbnflcldabbghjo",
  // Secure Shell (dev)
  "okddffdblfhhnmhodogpojmfkjmhinfp"
]);
 
var SSH2_AGENTC_REQUEST_IDENTITIES = 11;
var SSH2_AGENTC_SIGN_REQUEST = 13;
var SSH2_AGENTC_ADD_IDENTITY = 17;
var SSH2_AGENTC_REMOVE_IDENTITY = 18;
var SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
var SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;

var SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
var SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
var SSH_AGENTC_LOCK = 22;
var SSH_AGENTC_UNLOCK = 23;
var SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

var SSH_AGENT_FAILURE = 5;
var SSH_AGENT_SUCCESS = 6;

var SSH2_AGENT_IDENTITIES_ANSWER = 12;
var SSH2_AGENT_SIGN_RESPONSE = 14;

var SSH_AGENT_CONSTRAIN_LIFETIME = 1;
var SSH_AGENT_CONSTRAIN_CONFIRM = 2;

var AGENT_MSG_TYPE = 'auth-agent@openssh.com';

var htonl = function(n) {
  return [
    (n & 0xFF000000) >>> 24,
    (n & 0x00FF0000) >>> 16,
    (n & 0x0000FF00) >>>  8,
    (n & 0x000000FF) >>>  0,
  ];
};

var AgentConnection = function(port) {
  this.port = port;

  if (!ALLOWED_CLIENTS.has(port.sender.id)) {
    console.warn("Received a connection from a disallowed extension: " + port.sender.id);
    port.disconnect();
    return;
  }

  this.port.onMessage.addListener(this.handleMessage.bind(this));
};

AgentConnection.prototype.handleMessage = function(msg) {
    // Sanity check the input
    if (msg.type != AGENT_MSG_TYPE) {
      this.port.disconnect();
      return;
    }

    switch (msg.data[0]) {
      case SSH2_AGENTC_REQUEST_IDENTITIES:
        this.handleRequestIdentities();
        break;
      case SSH2_AGENTC_SIGN_REQUEST:
        this.handleSignRequest(msg);
        break;
      default:
        this.handleInvalid();
        break;
    }
};

/*
 * REQUEST_IDENTITIES: List the identities stored in the agent
 *
 * Returns:
 *  byte SSH2_AGENT_IDENTITIES_ANSWER
 *  uint32 n
 *  {string key_blob, string key_comment}[n]
 */
AgentConnection.prototype.handleRequestIdentities = function() {
  chrome.platformKeys.selectClientCertificates({request: {certificateAuthorities: [], certificateTypes: []}, interactive: false}, function(x) {console.log(x);});

  this.port.postMessage({
    type: AGENT_MSG_TYPE,
    data: [SSH2_AGENT_IDENTITIES_ANSWER].concat(htonl(0))
  });
};

AgentConnection.prototype.listKeys = function(callback) {
  chrome.platformKeys.selectCertificates(
    {interactive: false},
    function(matches) {
      
    });
};

/*
 * SIGN_REQUEST: Sign data using a specified key
 *
 * Request:
 *  byte SSH2_AGENTC_SIGN_REQUEST
 *  string key_blob
 *  string data
 *  uint32 flags // (0 except for dss)
 *
 * Response:
 *  byte SSH2_AGENT_SIGN_RESPONSE
 *  string signature
 *
 * Signature is calculated using PKCS1v1.5 with SHA-1
 */
AgentConnection.prototype.handleSignRequest = function(msg) {
  // TODO: implement
  this.handleInvalid();
};

AgentConnection.prototype.handleInvalid = function() {
  this.port.postMessage({
    type: AGENT_MSG_TYPE,
    data: [SSH_AGENT_FAILURE]
  });
};

chrome.runtime.onConnectExternal.addListener(function(port) {
  new AgentConnection(port);
});
