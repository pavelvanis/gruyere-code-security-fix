def _GenerateXsrfToken(self, cookie):
  """Generates a timestamp and XSRF token for all state changing actions."""

  timestamp = time.time()
  return timestamp + "|" + (str(hash(cookie_secret + cookie + timestamp)))

def _VerifyXsrfToken(self, cookie, action_token):
  """Verifies an XSRF token included in a request."""

  # First, make sure that the token isn't more than a day old.
  (action_time, action_hash) = action_token.split("|", 1)
  now = time.time()
  if now - 86400 > float(action_time):
    return False

  # Second, regenerate it and check that it matches the user supplied value
  hash_to_verify = str(hash(cookie_secret + cookie + action_time)
  return action_hash == hash_to_verify