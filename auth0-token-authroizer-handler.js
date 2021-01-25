require('dotenv').config({ silent: true })
const _ = require('lodash')
const config = require('config')
const jwksClient = require('jwks-rsa')
const jwt = require('jsonwebtoken')
const util = require('util')
const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10, // Default value
  jwksUri: config.auth0.jwks_uri
})

exports.authenticateHandler = async function (event, context, callback) {
  const token = getToken(event)
  const decoded = jwt.decode(token, { complete: true })
  if (!decoded || !decoded.header || !decoded.header.kid) {
    throw new Error('invalid token')
  }
  const getSigningKey = util.promisify(client.getSigningKey)
  try {
    const key = await getSigningKey(decoded.header.kid)
    const jwtOptions = {
      audience: config.auth0.audience,
      issuer: config.auth0.issuer
    }
    const decodedKey = jwt.verify(token, key.publicKey || key.rsaPublicKey, jwtOptions)
    let userProfile
    try {
      userProfile = JSON.parse(_.get(decoded, 'payload')[`${config.cxztracNamespace}/profile`])
    } catch (error) {
      userProfile = {}
      console.log('Error getting cxztrac user profile, leave empty', error)
    }
    return {
      principalId: decodedKey.sub,
      policyDocument: getPolicyDocument('Allow', event.methodArn),
      context: { scope: decodedKey.scope, ...userProfile }
    }
  } catch (error) {
    console.log('Error get sign key', error)
    throw error
  }
}

// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
  if (!params.type || params.type !== 'TOKEN') {
    throw new Error('Expected "event.type" parameter to have value "TOKEN"')
  }

  const tokenString = params.authorizationToken
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set')
  }

  const match = tokenString.match(/^Bearer (.*)$/)
  if (!match || match.length < 2) {
    throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`)
  }
  return match[1]
}

const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: '2012-10-17', // default version
    Statement: [{
      Action: 'execute-api:Invoke', // default action
      Effect: effect,
      Resource: resource
    }]
  }
  return policyDocument
}
