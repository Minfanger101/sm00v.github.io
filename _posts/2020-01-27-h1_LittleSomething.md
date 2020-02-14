---
title: "HackerOne CTF Write-up: A little something to get you started"
date: 2020-01-27
category: [HackerOne CTF]
tags: [HackerOne, Web Application, view source]
header:
    teaser: "/assets/images/h1/h1.png"
---
The HackerOne CTF challenge "A little something to get you started" could not get much easier. Given its difficulty rating of "Trivial" I suppose this should come as no surprise. Nonetheless, the challenge introduces the importance of the powerful "View Page Source" option built into browsers.

![h1](/assets/images/h1/h1.png)

## Flag 0
The webpage that the user is initially directed to simply contains the message:

> Welcome to level 0. Enjoy your stay.

The source code of the webpage can be viewed by either right clicking the webpage and selecting the "View Page Source" option (shown below) or through the `command` + `U` key combination (`Ctrl` + `U` for Windows users).

![view_source](/assets/images/h1/littlesomething/view_source.png)

The source code of the webpage reveals that there is a bit more going on behind the scenes.

```html
<!doctype html>
<html>
	<head>
		<style>
			body {
				background-image: url("background.png");
			}
		</style>
	</head>
	<body>
		<p>Welcome to level 0.  Enjoy your stay.</p>
	</body>
</html>
```

Most notably, the background image called `background.png` is being used as the background for the webpage and is located in the web root directory. Browsing to the `background.png` URL (which is `http://34.74.105.127/d360948f34/background.png`, in this example) reveals the flag for the challenge.

```
^FLAG^89918b3bf<redacted>$FLAG$
```
