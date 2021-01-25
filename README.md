# Deploy
1. Envrionment variable:
AUTH0_AUDIENCE
AUTH0_TOKEN_ISSUER
AUTH0_JWKS_URI
ACCOUNT_ID
STAGE
2. Pre-requisits:
None (so far)
3. Command:
serverless deploy

# How does this one work?
This function serves as a middleware between api gateway and lambda functions. It act as "Authorizer" for client side api calls.