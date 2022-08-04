import os.path
import json

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import DeploymentMode
from azure.identity import DefaultAzureCredential

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
resource_group = os.getenv("AZURE_RESOURCE_GROUP")
identity = os.getenv("AZURE_MIDENTITY")

credentials = DefaultAzureCredential(managed_identity_client_id=identity)

client = ResourceManagementClient(credentials, subscription_id)
rg = client.resource_groups.create_or_update(resource_group, {"location": "westeurope"})

template_path = os.path.join(os.path.dirname(__file__), "template.json")
with open(template_path, "r", encoding="ascii") as template_file_fd:
    template = json.load(template_file_fd)

parameters = {
    "name": "adns-test-service",
    "location": rg.location,
    "image": "adnscontainers.azurecr.io/adns-test-service:latest",
    "port": 22,
    "cpuCores": 1,
    "memoryInGb": 2,
    "restartPolicy": "Never",
    "identity": identity,
}
parameters = {k: {"value": v} for k, v in parameters.items()}

deployment_properties = {
    "mode": DeploymentMode.incremental,
    "template": template,
    "parameters": parameters,
}

deployment_async_operation = client.deployments.begin_create_or_update(
    resource_group,
    "adns-test-service-deployment",
    {"properties": deployment_properties},
)

deployment_async_operation.wait()
