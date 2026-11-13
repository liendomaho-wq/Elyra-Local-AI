"""Checks de seguridad pasivos y validaciones activas seguras."""

from . import cookies, cors, disclosure, headers, methods, ports, redirect, sqli, tls, xss

REGISTRY = {
    "headers": headers.run,
    "cookies": cookies.run,
    "tls": tls.run,
    "ports": ports.run,
    "disclosure": disclosure.run,
    "cors": cors.run,
    "methods": methods.run,
    "xss": xss.run,
    "sqli": sqli.run,
    "redirect": redirect.run,
}
