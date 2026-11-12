import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from risk_engine import evaluate
from url_analyzer import extract_url

def handler(request):
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json",
    }
    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": headers, "body": ""}
    if request.method != "POST":
        return {"statusCode": 405, "headers": headers, "body": json.dumps({"error": "Method not allowed"})}
    try:
        body = json.loads(request.body)
    except Exception:
        return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "Invalid JSON"})}
    url = body.get("url")
    message = body.get("message")
    if message:
        url = extract_url(message)
        if not url:
            return {"statusCode": 200, "headers": headers, "body": json.dumps({"error": "no_url", "message": "No URL found in the message."})}
    if not url:
        return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "Provide 'url' or 'message' in request body."})}
    result = evaluate(url)
    return {"statusCode": 200, "headers": headers, "body": json.dumps(result)}
