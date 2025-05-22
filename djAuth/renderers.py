from rest_framework.renderers import JSONRenderer as BaseJSONRenderer


class JSONRenderer(BaseJSONRenderer):
    """
    JSON response rendering module to maintain consistency across responses.

    Responses:
    - 2XX: {"message": str, "data": dict or list}
    - 4XX/5XX: {"message": str, "data": dict or list}
    """

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = renderer_context["response"]
        status_code = response.status_code
        is_error = response.exception

        layout = {
            "message": "",
            "data": {}
        }

        def extract_message_and_data(default_msg):
            if isinstance(data, str):
                return data, {}
            elif isinstance(data, dict):
                d = data.copy()
                return d.pop("message", default_msg), d
            elif isinstance(data, (list, tuple)):
                return default_msg, data
            else:
                return f"{default_msg}_Unprocessed", data

        if is_error:
            layout["message"], layout["data"] = (
                data.get("detail", "Error") if isinstance(
                    data, dict) else "Error",
                data if not isinstance(data, str) else {}
            )
        else:
            default_msg = "Ok" if 200 <= status_code < 300 else "Error"
            layout["message"], layout["data"] = extract_message_and_data(
                default_msg)

        return super().render(layout, accepted_media_type, renderer_context)
