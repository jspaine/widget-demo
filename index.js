import _config from "config"
import crypto from "crypto"
import express from "express"
import {SignJWT, importJWK, base64url} from "jose"

const config = {
  apiGatewayUrl: _config.get("apiGatewayUrl"),
  authClientId: _config.get("authClientId"),
  clientId: _config.get("clientId"),
  identityUrl: _config.get("identityUrl"),
  port: process.env.PORT || _config.get("port"),
  privateKey: _config.get("privateKey"),
  userId: _config.get("userId"),
  widgetScriptsUrl: _config.get("widgetScriptsUrl"),
}

const random = (length = 32) =>
  base64url.encode(crypto.randomBytes(length))

const app = express()
app.set("view engine", "ejs")
app.use(express.static("public"))

app.get("/jwt", (req, res) => {
  const {
    authClientId: clientId,
    identityUrl,
    privateKey,
    userId
  } = config
  const {alg, kid} = privateKey

  return importJWK(privateKey)
    .then(key =>
      new SignJWT({})
        .setProtectedHeader({alg, kid})
        .setSubject(userId)
        .setIssuer(clientId)
        .setAudience(identityUrl)
        .setIssuedAt()
        .setJti(random())
        .setExpirationTime('5m')
        .sign(key)
    )
    .then(jwt => res.send({jwt}))
    .catch(err => res.status(500).send({error: err.message}))
})

app.get("/accounts-and-assets.html", (req, res) => {
  const {apiGatewayUrl, identityUrl, widgetScriptsUrl} = config
  res.render("accounts-and-assets", {
    apiGatewayUrl,
    identityUrl,
    widgetScriptsUrl,
  })
})

app.listen(config.port, () => {
  console.log("Listening on port: ", config.port)
})