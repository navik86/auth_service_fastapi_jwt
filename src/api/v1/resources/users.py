from fastapi import APIRouter, Depends

from src.api.v1.schemas import UserCreate
from src.api.v1.schemas.users import UserModel
from src.services.user import UserService, get_user_service

router = APIRouter()

# Создаем эндпойнты согласно файлу настроек postman collection


@router.post(
    path="/signup",
    summary="Регистрация на сайте",
    tags=["users"],
)
def signup(user: UserCreate, user_service: UserService = Depends(get_user_service)) -> dict:
    response = {"msg": "User created."}
    user: dict = user_service.create_user(user=user)
    response.update({"user": UserModel(**user)})
    return response

@router.post(
    path="/login",
    summary="Зайти на сайт",
    tags=["users"],
)
def login():
    pass


@router.post(
    path="/refresh",
    summary="Обновляет токен",
    tags=["users"],
)
def refresh():
    pass


@router.get(
    path="/users/me",
    summary="Смотреть свой профиль",
    tags=["users"],
)
def get_user_info():
    pass


@router.patch(
    path="/users/me",
    summary="Обновить информацию профиля",
    tags=["users"],
)
def update_user_info():
    pass


@router.post(
    path="/logout",
    # response_model= ,
    summary="Выйти из аккаунта",
    tags=["users"],
)
def logout():
    pass


@router.post(
    path="/logout_all",
    # response_model= ,
    summary="Выйти со всех устройств",
    tags=["users"],
)
def logout_all():
    pass
