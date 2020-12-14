const crypto = require('crypto');
const { default: fromKeyLike } = require('jose/jwk/from_key_like');
const { default: SignJWT } = require('jose/jwt/sign');

const radix = 10;
const PORT = parseInt(process.env.REACT_APP_DEV_API_SERVER_PORT, radix);
const rootUrl = process.env.REACT_APP_CANONICAL_ROOT_URL;
const useDevApiServer = process.env.NODE_ENV === 'development' && !!PORT;

const issuerUrl = useDevApiServer ? `http://localhost:${PORT}/api` : `${rootUrl}/api`;

/**
 * Gets user information and creates the signed jwt for id token.
 *
 * @param {string} idpClientId the client id of the idp provider in Console
 * @param {Object} options signing options containing signingAlg and required key information
 * @param {Object} user user information containing at least firstName, lastName, email and emailVerified
 *
 * @return {Promise} idToken
 */
exports.createIdToken = (idpClientId, options, user) => {
  if (!idpClientId) {
    console.error('Missing idp client id!');
    return;
  }
  if (!user) {
    console.error('Missing user information!');
    return;
  }

  const signingAlg = options.signingAlg;

  // Currently Flex supports only RS256 signing algorithm.
  if (signingAlg !== 'RS256') {
    console.error(`${signingAlg} is not currently supported!`);
    return;
  }

  const { rsaPrivateKey, keyId } = options;

  if (!rsaPrivateKey) {
    console.error('Missing RSA private key!');
    return;
  }

  // We use jose library which requires the RSA key
  // to be KeyLike format:
  // https://github.com/panva/jose/blob/master/docs/types/_types_d_.keylike.md
  const privateKey = crypto.createPrivateKey(rsaPrivateKey);

  const { userId, firstName, lastName, email, emailVerified } = user;

  const jwt = new SignJWT({
    given_name: firstName,
    family_name: lastName,
    email: email,
    email_verified: emailVerified,
  })
    .setProtectedHeader({ alg: signingAlg, kid: keyId })
    .setIssuedAt()
    .setIssuer(issuerUrl)
    .setSubject(userId)
    .setAudience(idpClientId)
    .setExpirationTime('1h')
    .sign(privateKey);

  return jwt;
};

// Serves the discovery document in json format
// this document is expected to be found from
// api/.well-known/openid-configuration endpoint
exports.openIdConfiguration = (req, res) => {
  res.json({
    issuer: issuerUrl,
    jwks_uri: `${issuerUrl}/.well-known/jwks.json`,
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  });
};

// Serves the RSA public key as JWK
// this document is expected to be found from
// api/.well-known/jwks.json endpoint as stated in discovery document
exports.jwksUri = (rsaPublicKey, keyId) => (req, res) => {
  fromKeyLike(crypto.createPublicKey(rsaPublicKey)).then(jwkPublicKey => {
    res.json({ keys: [{ alg: 'RS256', kid: keyId, use: 'sig', ...jwkPublicKey }] });
  });
};
