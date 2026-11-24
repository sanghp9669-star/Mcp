"""Locust load test targeting MCP health & endpoint throughput."""

from locust import HttpUser, between, task


class SwitchMCPLoadUser(HttpUser):
    wait_time = between(0.5, 2.0)

    @task(3)
    def probe_liveness(self) -> None:
        self.client.get("/liveness")

    @task(2)
    def scrape_metrics(self) -> None:
        self.client.get("/metrics")
