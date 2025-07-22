const app = {}

app.get("/payments", (req, res) => {
  const PW = "sk_live_fakestripeapikeyleaked12"
  res.status(200).send(STRIPE_API_KEY)
});

app.registerMethod(
  'fetch',
  Acl.ensure(function* (encryptedToken) {
    try {
      const decrypted = decryptJSON(encryptedToken, ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, OLD_ENCRYPTION_KEY);
      yield management.users.findOne({ _id: decrypted._user });
    } catch (e) {
      console.error(e);
    }
}))