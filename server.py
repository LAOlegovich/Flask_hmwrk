import pydantic
from flask import Flask, jsonify, request
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError

from models import Session, User, Sticker
from schema import CreateUser, UpdateUser, CreateSticker, UpdateSticker

app = Flask("app")
bcrypt = Bcrypt(app)


def hash_password(password: str):
    password = password.encode()
    return bcrypt.generate_password_hash(password).decode()


def check_password(password: str, hashed_password: str):
    password = password.encode()
    hashed_password = hashed_password.encode()
    return bcrypt.check_password_hash(password, hashed_password)


def validate(schema_class, json_data):
    try:
        return schema_class(**json_data).dict(exclude_unset=True)
    except pydantic.ValidationError as er:
        error = er.errors()[0]
        error.pop("ctx", None)
        raise HttpError(400, error)


class HttpError(Exception):
    def __init__(self, status_code: int, description: str):
        self.status_code = status_code
        self.description = description


@app.errorhandler(HttpError)
def error_handler(error: HttpError):
    response = jsonify({"error": error.description})
    response.status_code = error.status_code
    return response


@app.before_request
def before_request():
    session = Session()
    request.session = session


@app.after_request
def after_request(response):
    request.session.close()
    return response


def get_instance_by_id(instance_id: int, instance_class):
    instance = request.session.get(instance_class, instance_id)
    if instance is None:
        raise HttpError(404, f"instance of {instance_class} not found")
    return instance


def add_instance(instance):
    try:
        request.session.add(instance)
        request.session.commit()
    except IntegrityError as err:
        raise HttpError(409, "instance already exists")
    return instance


class UserView(MethodView):
    def get(self, user_id: int):
        user = get_instance_by_id(user_id, User)
        return jsonify(user.json)

    def post(self):
        json_data = validate(CreateUser, request.json)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        add_instance(user)
        response = jsonify(user.json)
        response.status_code = 201
        return response

    def patch(self, user_id: int):
        json_data = validate(UpdateUser, request.json)
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])
        user = get_instance_by_id(user_id, User)
        for field, value in json_data.items():
            setattr(user, field, value)
        add_instance(user)
        return jsonify(user.json)

    def delete(self, user_id: int):
        user = get_instance_by_id(user_id, User)
        request.session.delete(user)
        request.session.commit()
        return jsonify({"status": "success"})



class StickerView(MethodView):

    def get(self, sticker_id:int):
        sticker = get_instance_by_id(sticker_id, Sticker)
        return jsonify(sticker.json)

    def post(self):
        json_data = validate(CreateSticker, request.json)
        sticker = Sticker(**json_data)
        add_instance(sticker)
        response = jsonify(sticker.json)
        return response
    
    def patch(self, sticker_id: int):
        json_data = validate(UpdateSticker, request.json)
        sticker = get_instance_by_id(sticker_id, Sticker)
        for field, value in json_data.items():
            setattr(sticker, field, value)
        add_instance(sticker)
        return jsonify(sticker.json)
    
    def delete(self, sticker_id:int):
        sticker = get_instance_by_id(sticker_id, Sticker)
        request.session.delete(sticker)
        request.session.commit()
        return jsonify({'status':'success'})




user_view = UserView.as_view("user_view")

sticker_view = StickerView.as_view("sticker_view")

app.add_url_rule(
    "/user",
    view_func=user_view,
    methods=[
        "POST",
    ],
)
app.add_url_rule(
    "/user/<int:user_id>", view_func=user_view, methods=["GET", "PATCH", "DELETE"]
)

app.add_url_rule("/sticker", view_func= sticker_view, methods = ["POST",])

app.add_url_rule(
    "/sticker/<int:sticker_id>", view_func=sticker_view, methods=["GET", "PATCH", "DELETE"]
)


app.run()
