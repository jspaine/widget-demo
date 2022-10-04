import _config from "config"
import crypto from "crypto"
import express from "express"
import {SignJWT, importJWK, base64url} from "jose"
import cors from "cors"
import qs from "qs"

const config = {
  apiGatewayUrl: _config.get("apiGatewayUrl"),
  authClientId: _config.get("authClientId"),
  identityUrl: _config.get("identityUrl"),
  port: process.env.PORT || _config.get("port"),
  privateKey: _config.get("privateKey"),
  userId: _config.get("userId"),
  widgetScriptsUrl: _config.get("widgetScriptsUrl"),
  paymentWidget: _config.get("paymentWidget")
}

const random = (length = 32) =>
  base64url.encode(crypto.randomBytes(length))

const app = express()
app.set("view engine", "ejs")
app.use(cors())
app.use(express.static("public"))

app.get("/jwt", (req, res) => {
  // In a real world scenario the userId should be retrieved from the
  // user session once that the user has authenticated
  const {
    authClientId: clientId,
    identityUrl,
    privateKey,
    userId
  } = config
  const {alg, kid} = privateKey
  const audience = `${identityUrl}/oidc`

  return importJWK(privateKey)
    .then(key =>
      new SignJWT({})
        .setProtectedHeader({alg, kid})
        .setSubject(userId)
        .setIssuer(clientId)
        .setAudience(audience)
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

app.get("/payment-widget", (req, res) => {
  const {clientId, clientSecret, payeeId, redirectUri} = config.paymentWidget

  const {apiGatewayUrl, identityUrl, widgetScriptsUrl} = config
  res.render("payment-widget", {
    apiGatewayUrl,
    identityUrl,
    widgetScriptsUrl,
    clientId,
    clientSecret,
    payeeId,
    redirectUri
  })
})

app.get("/cordova-payment-widget/callback", (req, res) => {

  const queryString = qs.stringify(req.query)
  const redirectUrl = `moneyhubwidgets://callback?${queryString}`
  res.render("cordova-payment-widget-callback", {redirectUrl})
})

app.get("/cordova-payment-widget/redirect", (req, res) => {

  const queryString = qs.stringify(req.query)
  const redirectUrl = `moneyhubwidgets://callback?${queryString}`
  res.redirect(redirectUrl)
})

app.listen(config.port, () => {
  console.log("Listening on port: ", config.port)
})