import socketserver
import http.server
import json

from providers import auth_provider
from providers import data_provider

from processors import notification_processor


class ApiRequestHandler(http.server.BaseHTTPRequestHandler):

    def handle_get_version_1(self, path, user):
        if not auth_provider.has_access(user, path, "get"):
            self.send_response(403)
            self.end_headers()
            return
        if path[0] == "warehouses":
            paths = len(path)
            match paths:
                case 1:
                    warehouses = data_provider.fetch_warehouse_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(warehouses).encode("utf-8"))
                case 2:
                    warehouse_id = int(path[1])
                    warehouse = data_provider.fetch_warehouse_pool().get_data_by_ID(warehouse_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(warehouse).encode("utf-8"))
                case 3:
                    if path[2] == "locations":
                        warehouse_id = int(path[1])
                        locations = data_provider.fetch_location_pool().get_locations_in_warehouse(warehouse_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(locations).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "locations":
            paths = len(path)
            match paths:
                case 1:
                    locations = data_provider.fetch_location_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(locations).encode("utf-8"))
                case 2:
                    location_id = int(path[1])
                    location = data_provider.fetch_location_pool().get_data_by_ID(location_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(location).encode("utf-8"))
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "transfers":
            paths = len(path)
            match paths:
                case 1:
                    transfers = data_provider.fetch_transfer_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(transfers).encode("utf-8"))
                case 2:
                    transfer_id = int(path[1])
                    transfer = data_provider.fetch_transfer_pool().get_data_by_ID(transfer_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(transfer).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        transfer_id = int(path[1])
                        items = data_provider.fetch_transfer_pool().get_items_in_transfer(transfer_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "items":
            paths = len(path)
            match paths:
                case 1:
                    items = data_provider.fetch_item_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(items).encode("utf-8"))
                case 2:
                    item_id = path[1]
                    item = data_provider.fetch_item_pool().get_data_by_ID(item_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item).encode("utf-8"))
                case 3:
                    if path[2] == "inventory":
                        item_id = path[1]
                        inventories = data_provider.fetch_inventory_pool().get_inventories_for_item(item_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(inventories).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case 4:
                    if path[2] == "inventory" and path[3] == "totals":
                        item_id = path[1]
                        totals = data_provider.fetch_inventory_pool().get_inventory_totals_for_item(item_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(totals).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "item_lines":
            paths = len(path)
            print(paths, path)

            match paths:
                case 1:
                    item_lines = data_provider.fetch_item_line_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_lines).encode("utf-8"))
                case 2:
                    item_line_id = int(path[1])
                    item_line = data_provider.fetch_item_line_pool().get_data_by_ID(item_line_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_line).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        item_line_id = int(path[1])
                        items = data_provider.fetch_item_pool().get_items_for_item_line(item_line_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "item_groups":
            paths = len(path)
            match paths:
                case 1:
                    item_groups = data_provider.fetch_item_group_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_groups).encode("utf-8"))
                case 2:
                    item_group_id = int(path[1])
                    item_group = data_provider.fetch_item_group_pool().get_data_by_ID(item_group_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_group).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        item_group_id = int(path[1])
                        items = data_provider.fetch_item_pool().get_items_for_item_group(item_group_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "item_types":
            paths = len(path)
            match paths:
                case 1:
                    item_types = data_provider.fetch_item_type_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_types).encode("utf-8"))
                case 2:
                    item_type_id = int(path[1])
                    item_type = data_provider.fetch_item_type_pool().get_data_by_ID(item_type_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(item_type).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        item_type_id = int(path[1])
                        items = data_provider.fetch_item_pool().get_items_for_item_type(item_type_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "inventories":
            paths = len(path)
            match paths:
                case 1:
                    inventories = data_provider.fetch_inventory_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(inventories).encode("utf-8"))
                case 2:
                    inventory_id = int(path[1])
                    inventory = data_provider.fetch_inventory_pool().get_data_by_ID(inventory_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(inventory).encode("utf-8"))
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "suppliers":
            paths = len(path)
            match paths:
                case 1:
                    suppliers = data_provider.fetch_supplier_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(suppliers).encode("utf-8"))
                case 2:
                    supplier_id = int(path[1])
                    supplier = data_provider.fetch_supplier_pool().get_data_by_ID(supplier_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(supplier).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        supplier_id = int(path[1])
                        items = data_provider.fetch_item_pool().get_items_for_supplier(supplier_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "orders":
            paths = len(path)
            match paths:
                case 1:
                    orders = data_provider.fetch_order_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(orders).encode("utf-8"))
                case 2:
                    order_id = int(path[1])
                    order = data_provider.fetch_order_pool().get_data_by_ID(order_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(order).encode("utf-8"))
                case 3:
                    if path[2] == "items":
                        order_id = int(path[1])
                        items = data_provider.fetch_order_pool().get_items_in_order(order_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "clients":
            paths = len(path)
            match paths:
                case 1:
                    clients = data_provider.fetch_client_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(clients).encode("utf-8"))
                case 2:
                    client_id = int(path[1])
                    client = data_provider.fetch_client_pool().get_data_by_ID(client_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(client).encode("utf-8"))
                case 3:
                    if path[2] == "orders":
                        client_id = int(path[1])
                        orders = data_provider.fetch_order_pool().get_orders_for_client(client_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(orders).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "shipments":
            paths = len(path)
            match paths:
                case 1:
                    shipments = data_provider.fetch_shipment_pool().get_data()
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(shipments).encode("utf-8"))
                case 2:
                    shipment_id = int(path[1])
                    shipment = data_provider.fetch_shipment_pool().get_data_by_ID(shipment_id)
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(shipment).encode("utf-8"))
                case 3:
                    if path[2] == "orders":
                        shipment_id = int(path[1])
                        orders = data_provider.fetch_order_pool().get_orders_in_shipment(shipment_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(orders).encode("utf-8"))
                    elif path[2] == "items":
                        shipment_id = int(path[1])
                        items = data_provider.fetch_shipment_pool().get_items_in_shipment(shipment_id)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(items).encode("utf-8"))
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        api_key = self.headers.get("API_KEY")
        user = auth_provider.get_user(api_key)
        if user == None:
            self.send_response(401)
            self.end_headers()
        else:
            try:
                path = self.path.split("/")
                if len(path) > 3 and path[1] == "api" and path[2] == "v1":
                    self.handle_get_version_1(path[3:], user)
            except Exception:
                self.send_response(500)
                self.end_headers()

    def handle_post_version_1(self, path, user):
        if not auth_provider.has_access(user, path, "post"):
            self.send_response(403)
            self.end_headers()
            return
        if path[0] == "warehouses":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_warehouse = json.loads(post_data.decode())
            data_provider.fetch_warehouse_pool().add_data(new_warehouse)
            data_provider.fetch_warehouse_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "locations":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_location = json.loads(post_data.decode())
            data_provider.fetch_location_pool().add_data(new_location)
            data_provider.fetch_location_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "transfers":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_transfer = json.loads(post_data.decode())
            data_provider.fetch_transfer_pool().add_data(new_transfer)
            data_provider.fetch_transfer_pool().save()
            notification_processor.push(f"Scheduled batch transfer {new_transfer['id']}")
            self.send_response(201)
            self.end_headers()
        elif path[0] == "items":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_item = json.loads(post_data.decode())
            data_provider.fetch_item_pool().add_data(new_item)
            data_provider.fetch_item_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "inventories":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_inventory = json.loads(post_data.decode())
            data_provider.fetch_inventory_pool().add_data(new_inventory)
            data_provider.fetch_inventory_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "suppliers":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_supplier = json.loads(post_data.decode())
            data_provider.fetch_supplier_pool().add_data(new_supplier)
            data_provider.fetch_supplier_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "orders":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_order = json.loads(post_data.decode())
            data_provider.fetch_order_pool().add_data(new_order)
            data_provider.fetch_order_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "clients":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_client = json.loads(post_data.decode())
            data_provider.fetch_client_pool().add_data(new_client)
            data_provider.fetch_client_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "shipments":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_shipment = json.loads(post_data.decode())
            data_provider.fetch_shipment_pool().add_data(new_shipment)
            data_provider.fetch_shipment_pool().save()
            self.send_response(201)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        authorization_header = self.headers.get("Authorization")
        if authorization_header:
            api_key = authorization_header.split(" ")[1]
            user = auth_provider.get_user(api_key)
            if user == None:
                self.send_response(401)
                self.end_headers()
            else:
                try:
                    path = self.path.split("/")
                    if len(path) > 3 and path[1] == "api" and path[2] == "v1":
                        if path[3:] is not None and len(path[3:]) > 0:
                            self.handle_post_version_1(path[3:], user)
                        else:
                            self.send_response(400)
                            self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
                except Exception as e:
                    print(f"Error: {e}")
                    self.send_response(500)
                    self.end_headers()
        else:
            self.send_response(401)
            self.end_headers()

    def handle_put_version_1(self, path, user):
        if not auth_provider.has_access(user, path, "put"):
            self.send_response(403)
            self.end_headers()
            return
        if path[0] == "warehouses":
            warehouse_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_warehouse = json.loads(post_data.decode())
            data_provider.fetch_warehouse_pool().update_data(warehouse_id, updated_warehouse)
            data_provider.fetch_warehouse_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "locations":
            location_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_location = json.loads(post_data.decode())
            data_provider.fetch_location_pool().update_data(location_id, updated_location)
            data_provider.fetch_location_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "transfers":
            paths = len(path)
            match paths:
                case 2:
                    transfer_id = int(path[1])
                    content_length = int(self.headers["Content-Length"])
                    post_data = self.rfile.read(content_length)
                    updated_transfer = json.loads(post_data.decode())
                    data_provider.fetch_transfer_pool().update_data(transfer_id, updated_transfer)
                    data_provider.fetch_transfer_pool().save()
                    self.send_response(200)
                    self.end_headers()
                case 3:
                    if path[2] == "commit":
                        transfer_id = int(path[1])
                        transfer = data_provider.fetch_transfer_pool().get_data(transfer_id)
                        for x in transfer["items"]:
                            inventories = data_provider.fetch_inventory_pool().get_inventories_for_item(x["item_id"])
                            for y in inventories:
                                if y["location_id"] == transfer["transfer_from"]:
                                    y["total_on_hand"] -= x["amount"]
                                    y["total_expected"] = y["total_on_hand"] + y["total_ordered"]
                                    y["total_available"] = y["total_on_hand"] - y["total_allocated"]
                                    data_provider.fetch_inventory_pool().update_data(y["id"], y)
                                elif y["location_id"] == transfer["transfer_to"]:
                                    y["total_on_hand"] += x["amount"]
                                    y["total_expected"] = y["total_on_hand"] + y["total_ordered"]
                                    y["total_available"] = y["total_on_hand"] - y["total_allocated"]
                                    data_provider.fetch_inventory_pool().update_data(y["id"], y)
                        transfer["transfer_status"] = "Processed"
                        data_provider.fetch_transfer_pool().update_data(transfer_id, transfer)
                        notification_processor.push(f"Processed batch transfer with id:{transfer['id']}")
                        data_provider.fetch_transfer_pool().save()
                        data_provider.fetch_inventory_pool().save()
                        self.send_response(200)
                        self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "items":
            item_id = path[1]
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_item = json.loads(post_data.decode())
            data_provider.fetch_item_pool().update_data(item_id, updated_item)
            data_provider.fetch_item_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "item_lines":
            item_line_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_item_line = json.loads(post_data.decode())
            data_provider.fetch_item_line_pool().update_data(item_line_id, updated_item_line)
            data_provider.fetch_item_line_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "item_groups":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            new_item_group = json.loads(post_data.decode())
            data_provider.fetch_item_group_pool().update_data(new_item_group)
            data_provider.fetch_item_group_pool().save()
            self.send_response(201)
            self.end_headers()
        elif path[0] == "item_types":
            item_type_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_item_type = json.loads(post_data.decode())
            data_provider.fetch_item_type_pool().update_data(item_type_id, updated_item_type)
            data_provider.fetch_item_type_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "inventories":
            inventory_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_inventory = json.loads(post_data.decode())
            data_provider.fetch_inventory_pool().update_data(inventory_id, updated_inventory)
            data_provider.fetch_inventory_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "suppliers":
            supplier_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_supplier = json.loads(post_data.decode())
            data_provider.fetch_supplier_pool().update_data(supplier_id, updated_supplier)
            data_provider.fetch_supplier_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "orders":
            paths = len(path)
            match paths:
                case 2:
                    order_id = int(path[1])
                    content_length = int(self.headers["Content-Length"])
                    post_data = self.rfile.read(content_length)
                    updated_order = json.loads(post_data.decode())
                    data_provider.fetch_order_pool().update_data(order_id, updated_order)
                    data_provider.fetch_order_pool().save()
                    self.send_response(200)
                    self.end_headers()
                case 3:
                    if path[2] == "items":
                        order_id = int(path[1])
                        content_length = int(self.headers["Content-Length"])
                        post_data = self.rfile.read(content_length)
                        updated_items = json.loads(post_data.decode())
                        data_provider.fetch_order_pool().update_items_in_order(order_id, updated_items)
                        data_provider.fetch_order_pool().save()
                        self.send_response(200)
                        self.end_headers()
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        elif path[0] == "clients":
            client_id = int(path[1])
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            updated_client = json.loads(post_data.decode())
            data_provider.fetch_client_pool().update_data(client_id, updated_client)
            data_provider.fetch_client_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "shipments":
            paths = len(path)
            match paths:
                case 2:
                    shipment_id = int(path[1])
                    content_length = int(self.headers["Content-Length"])
                    post_data = self.rfile.read(content_length)
                    updated_shipment = json.loads(post_data.decode())
                    data_provider.fetch_shipment_pool().update_data(shipment_id, updated_shipment)
                    data_provider.fetch_shipment_pool().save()
                    self.send_response(200)
                    self.end_headers()
                case 3:
                    if path[2] == "orders":
                        shipment_id = int(path[1])
                        content_length = int(self.headers["Content-Length"])
                        post_data = self.rfile.read(content_length)
                        updated_orders = json.loads(post_data.decode())
                        data_provider.fetch_order_pool().update_orders_in_shipment(shipment_id, updated_orders)
                        data_provider.fetch_order_pool().save()
                        self.send_response(200)
                        self.end_headers()
                    elif path[2] == "items":
                        shipment_id = int(path[1])
                        content_length = int(self.headers["Content-Length"])
                        post_data = self.rfile.read(content_length)
                        updated_items = json.loads(post_data.decode())
                        data_provider.fetch_shipment_pool().update_items_in_shipment(shipment_id, updated_items)
                        data_provider.fetch_shipment_pool().save()
                        self.send_response(200)
                        self.end_headers()
                    elif path[2] == "commit":
                        pass
                    else:
                        self.send_response(404)
                        self.end_headers()
                case _:
                    self.send_response(404)
                    self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        # Log request for debugging purposes
        print(f"Received PUT request for {self.path}")
        
        # Retrieve the Authorization header
        authorization_header = self.headers.get("Authorization")
        
        # Check if Authorization header exists
        if authorization_header:
            try:
                # Split the Authorization header to extract the API key
                if "Bearer " in authorization_header:
                    api_key = authorization_header.split(" ")[1]
                else:
                    # If the Authorization format is wrong, return 400 Bad Request
                    print("Invalid Authorization format")
                    self.send_response(400)
                    self.end_headers()
                    return
                
                # Get the user based on the API key
                user = auth_provider.get_user(api_key)
                
                # If the user is not found, return 401 Unauthorized
                if user is None:
                    print("Unauthorized: Invalid API Key")
                    self.send_response(401)
                    self.end_headers()
                    return
                
                # Split and parse the path
                path = self.path.split("/")
                print(f"Parsed path: {path}")
                
                # Ensure the path is long enough and starts with /api/v1/
                if len(path) > 3 and path[1] == "api" and path[2] == "v1":
                    # Further handle the path and validate the resource
                    if path[3:] and len(path[3:]) > 0:
                        print(f"Handling PUT for {path[3:]}")
                        self.handle_put_version_1(path[3:], user)  # Assuming this function handles the PUT request logic
                    else:
                        print("Invalid path or resource")
                        self.send_response(400)  # Bad Request for invalid path/resource
                        self.end_headers()
                else:
                    print("Resource not found")
                    self.send_response(404)  # Not Found if path structure is wrong
                    self.end_headers()
            
            # Catch and log any unforeseen exceptions
            except Exception as e:
                print(f"Error in PUT request: {e}")
                self.send_response(500)  # Internal Server Error
                self.end_headers()
        
        # If Authorization header is missing, return 401 Unauthorized
        else:
            print("Missing Authorization header")
            self.send_response(401)
            self.end_headers()
        #Dit kan makkelijker
    def handle_delete_version_1(self, path, user):
        if not auth_provider.has_access(user, path, "delete"):
            self.send_response(403)
            self.end_headers()
            return
        if path[0] == "warehouses":
            warehouse_id = int(path[1])
            data_provider.fetch_warehouse_pool().remove_data(warehouse_id)
            data_provider.fetch_warehouse_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "locations":
            location_id = int(path[1])
            data_provider.fetch_location_pool().remove_data(location_id)
            data_provider.fetch_location_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "transfers":
            transfer_id = int(path[1])
            data_provider.fetch_transfer_pool().remove_data(transfer_id)
            data_provider.fetch_transfer_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "items":
            item_id = path[1]
            data_provider.fetch_item_pool().remove_data(item_id)
            data_provider.fetch_item_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "item_lines":
            item_line_id = int(path[1])
            data_provider.fetch_item_line_pool().remove_data(item_line_id)
            data_provider.fetch_item_line_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "item_groups":
            item_group_id = int(path[1])
            data_provider.fetch_item_group_pool().remove_data(item_group_id)
            data_provider.fetch_item_group_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "item_types":
            item_type_id = int(path[1])
            data_provider.fetch_item_type_pool().remove_data(item_type_id)
            data_provider.fetch_item_type_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "inventories":
            inventory_id = int(path[1])
            data_provider.fetch_inventory_pool().remove_data(inventory_id)
            data_provider.fetch_inventory_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "suppliers":
            supplier_id = int(path[1])
            data_provider.fetch_supplier_pool().remove_data(supplier_id)
            data_provider.fetch_supplier_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "orders":
            order_id = int(path[1])
            data_provider.fetch_order_pool().remove_data(order_id)
            data_provider.fetch_order_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "clients":
            client_id = int(path[1])
            data_provider.fetch_client_pool().remove_data(client_id)
            data_provider.fetch_client_pool().save()
            self.send_response(200)
            self.end_headers()
        elif path[0] == "shipments":
            shipment_id = int(path[1])
            data_provider.fetch_shipment_pool().remove_data(shipment_id)
            data_provider.fetch_shipment_pool().save()
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        api_key = self.headers.get("API_KEY")
        user = auth_provider.get_user(api_key)
        if user == None:
            self.send_response(401)
            self.end_headers()
        else:
            try:
                path = self.path.split("/")
                if len(path) > 3 and path[1] == "api" and path[2] == "v1":
                    self.handle_delete_version_1(path[3:], user)
            except Exception:
                self.send_response(500)
                self.end_headers()


if __name__ == "__main__":
    PORT = 3000
    with socketserver.TCPServer(("", PORT), ApiRequestHandler) as httpd:
        auth_provider.init()
        data_provider.init()
        notification_processor.start()
        print(f"Serving on port {PORT}...")
        httpd.serve_forever()