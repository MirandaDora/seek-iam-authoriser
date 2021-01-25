module.exports = {
  auth0: {
    audience: process.env.AUTH0_AUDIENCE,
    issuer: process.env.AUTH0_TOKEN_ISSUER,
    jwks_uri: process.env.AUTH0_JWKS_URI
  },
  cxztracNamespace: 'https://cxztrac.com' // to be alianed with auth0 namespace
}
