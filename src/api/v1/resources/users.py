# from http import HTTPStatus
# from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

# from src.api.v1.schemas import UserCreate, UserListResponse, UserModel
# from src.services import PostService, get_post_service

router = APIRouter()

# Создаем эндпойнты согласно файлу настроек postman collection


@router.post(
    path="/signup",
    # response_model= ,
    summary="Регистрация на сайте",
    tags=["users"],
)
def signup():
    pass


@router.post(
    path="/login",
    # response_model= ,
    summary="Зайти на сайт",
    tags=["users"],
)
def login():
    pass


@router.post(
    path="/refresh",
    # response_model= ,
    summary="Обновляет токен",
    tags=["users"],
)
def refresh():
    pass


@router.get(
    path="/users/me",
    # response_model= ,
    summary="Смотреть свой профиль",
    tags=["users"],
)
def get_user_info():
    pass


@router.patch(
    path="/users/me",
    # response_model= ,
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
