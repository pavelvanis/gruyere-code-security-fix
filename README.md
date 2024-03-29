Gruyere - a web application with holes.

Copyright 2017 Google Inc. All Rights Reserved.

This code is licensed under the http://creativecommons.org/licenses/by-nd/3.0/us
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
http://code.google.com/terms.html

## 11.03 - Test

#### Reflected XSS

- change

```html
  <div class="message">{{_message}}</div>
```
  for
```html
  <div class="message">{{_message:text}}</div>
```
  in `error.gtl`

#### Stored XSS

- i have change sanitizing function to sanitization by third party library bleach (https://pypi.org/project/bleach/)

```py
def SanitizeHtml(s):
  """Makes html safe for embedding in a document.

  Filters the html to exclude all but a small subset of html by
  removing script tags/attributes.

  Args:
    s: some html to sanitize.

  Returns:
    The html with all unsafe html removed.
  """
    # List of allowed tags
    allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul']
    # List of allowed attributes
    allowed_attrs = {'*': ['class'], 'a': ['href', 'rel']}
    # Sanitize the HTML
    sanitized_html = bleach.clean(s, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    return sanitized_html
```

#### XSRF


