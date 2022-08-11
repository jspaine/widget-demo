import _config from "config"
import express from "express"
import crypto from "crypto"
import {SignJWT, importJWK, base64url} from "jose"

const config = {
  identityUrl: _config.get("identityUrl"),
  port: process.env.PORT || _config.get("port"),
  clientId: _config.get("clientId"),
  userId: _config.get("userId"),
  privateKey: _config.get("privateKey"),
  widgetId: _config.get("widgetId"),
}

const app = express()
app.set("view engine", "ejs")
app.use(express.json())

const random = (length = 32) =>
  base64url.encode(crypto.randomBytes(length))


app.post("/jwt", (req, res) => {

  const {privateKey, identityUrl, clientId, userId} = config
  return importJWK(privateKey)
    .then(key =>
      new SignJWT({})
        .setProtectedHeader({alg: privateKey.alg, kid: privateKey.kid})
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

app.get("/", (req, res) => {
  const {identityUrl, widgetId} = config
  res.render("index", {identityUrl, widgetId})
})

app.listen(config.port, () => {
  console.log("Listening on port: ", config.port)
})