import _config from "config"
import express from "express"
import {SignJWT, importJWK} from "jose"

const config = {
  identityUrl: _config.get("identityUrl"),
  issuer: _config.get("issuer"),
  port: process.env.PORT || _config.get("port"),
  privateKey: _config.get("privateKey"),
  widgetId: _config.get("widgetId"),
}

const app = express()
app.set("view engine", "ejs")
app.use(express.json())

app.post("/jwt", (req, res) => {
  const {userId} = req.body

  if (!userId) {
    return res.status(400).send({error: "userId is required"})
  }

  return importJWK(config.privateKey)
    .then(key =>
      new SignJWT({userId})
        .setProtectedHeader({alg: "RS256"})
        .setIssuedAt()
        .setIssuer(config.issuer)
        .setAudience(config.identityUrl)
        .setExpirationTime('1h')
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