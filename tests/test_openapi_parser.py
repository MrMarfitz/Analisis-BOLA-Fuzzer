import unittest

from bola_fuzzer.openapi_parser import discover_endpoint_candidates, discover_resource_dependencies


class OpenApiParserTest(unittest.TestCase):
    def test_discovers_id_parameter_candidates(self):
        spec = {
            "openapi": "3.0.3",
            "paths": {
                "/workshop/api/vehicles/{id}": {
                    "get": {"summary": "Get vehicle", "responses": {"200": {"description": "ok"}}}
                },
                "/identity/api/auth/login": {"post": {"summary": "Login"}},
            },
        }

        candidates = discover_endpoint_candidates(spec)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].method, "GET")
        self.assertEqual(candidates[0].path, "/workshop/api/vehicles/{id}")
        self.assertEqual(candidates[0].source_endpoint, "/workshop/api/vehicles")

    def test_discovers_resource_dependencies(self):
        spec = {"paths": {"/users/{user_id}/orders/{order_id}": {"get": {}}}}

        dependencies = discover_resource_dependencies(spec)

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].resource, "orders")
        self.assertEqual(dependencies[0].parent_resource, "users")


if __name__ == "__main__":
    unittest.main()
