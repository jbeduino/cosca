import docker

client = docker.from_env()

container = client.containers.run(
    "openapitools/openapi-petstore",
    detach=True,
    environment={"OPENAPI_BASE_PATH": "/v3"},
    ports={"80/tcp": 8080}
)

logs = container.logs()
print(logs.decode("utf-8"))

print(f"Container {container.id} is running")