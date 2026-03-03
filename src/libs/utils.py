import json
from worker import Response


def json_response(data, status=200):
    """Create a JSON response."""
    return Response.json(data, status=status)


def html_response(html_str, status=200):
    """Create an HTML response."""
    return Response(
        html_str, 
        status=status,
        headers={"content-type": "text/html; charset=utf-8"}
    )
