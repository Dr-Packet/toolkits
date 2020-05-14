import forti_api_tools

host = "1.85.4.4"

key = "asdfadsf"
tools = forti_api_tools.fnt_tools(host, key)

routes = tools.routes()

print (routes.static_routes)
