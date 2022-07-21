import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from starlette.status import HTTP_403_FORBIDDEN

from src.api.v1.schemas import (Token, UserCreate, UserLogin, UserModel,
                                UserUpdate)
from src.core.config import JWT_ALGORITHM, JWT_SECRET_KEY
from src.services.user import UserService, get_user_service

router = APIRouter()
reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

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
    response_model=Token,
    summary="Зайти на сайт",
    tags=["users"],
)
def login(user: UserLogin, user_service: UserService = Depends(get_user_service)) -> Token:
    user = user_service.authenticate_user(username=user.username, password=user.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user_data = dict(UserModel(**user.dict()))
    user_uuid = str(user_data["uuid"])
    user_data["uuid"] = user_uuid
    user_data["created_at"] = str(user_data["created_at"])
    refresh_uuid = str(uuid.uuid4())

    refresh_token = user_service.create_refresh_token(user_uuid, refresh_uuid)
    access_token = user_service.create_access_token(user_data, refresh_uuid)

    user_service.add_refresh_token(user_uuid, refresh_uuid)

    return Token(**{"access_token": access_token, "refresh_token": refresh_token})


@router.post(
    path="/refresh",
    response_model=Token,
    summary="Обновляет токен",
    tags=["users"],
)
def refresh(user_service: UserService = Depends(get_user_service),
            token: str = Depends(reusable_oauth2)) -> Token:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )
    user_uuid = payload["uuid"]
    jti = payload["jti"]

    user_service.remove_refresh_token(user_uuid, jti)

    user = user_service.get_user_by_uuid(user_uuid)
    user_data = dict(UserModel(**user.dict()))
    user_data["uuid"] = str(user_data["uuid"])
    user_data["created_at"] = str(user_data["created_at"])

    refresh_uuid = str(uuid.uuid4())
    refresh_token = user_service.create_refresh_token(user_uuid, refresh_uuid)
    access_token = user_service.create_access_token(user_data, refresh_uuid)

    user_service.add_refresh_token(user_uuid, refresh_uuid)

    return Token(**{"access_token": access_token, "refresh_token": refresh_token})


@router.get(
    path="/users/me",
    summary="Смотреть свой профиль",
    tags=["users"],
)
def get_user_info(user_service: UserService = Depends(get_user_service),
                  token: str = Depends(reusable_oauth2)):
    current_user = user_service.get_user_by_token(token)
    return {"user": UserModel(**current_user)}


@router.patch(
    path="/users/me",
    summary="Обновить информацию профиля",
    tags=["users"],
)
def update_user_info(new_data: UserUpdate,
                     user_service: UserService = Depends(get_user_service),
                     token: str = Depends(reusable_oauth2)) -> dict:
    """Updates user information"""
    current_user = user_service.get_user_by_token(token)
    new_user = user_service.update_user_info(current_user, new_data)
    new_user_data = dict(UserModel(**new_user))
    new_user_data["uuid"] = str(new_user_data["uuid"])
    new_user_data["created_at"] = str(new_user_data["created_at"])
    refresh_uuid = user_service.get_refresh_uuid_from_access_token(token)

    id_token = user_service.get_id_token(token)
    user_service.block_access_token(id_token)

    response = {"msg": "Update is successful. Please use new token."}
    response.update({"user": new_user_data})

    access_token = user_service.create_access_token(new_user_data, refresh_uuid)

    response.update({"access_token": access_token})

    return response


@router.post(
    path="/logout",
    summary="Выйти из аккаунта",
    tags=["users"],
)
def logout(user_service: UserService = Depends(get_user_service),
           token: str = Depends(reusable_oauth2)) -> dict:
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    jti = payload["jti"]
    uuid = payload["uuid"]
    refresh_uuid = payload["refresh_uuid"]
    user_service.block_access_token(jti)
    user_service.remove_refresh_token(uuid, refresh_uuid)
    return {"msg": "You have been logged out."}


@router.post(
    path="/logout_all",
    summary="Выйти со всех устройств",
    tags=["users"],
)
def logout_all(user_service: UserService = Depends(get_user_service),
               token: str = Depends(reusable_oauth2)) -> dict:
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    jti = payload["jti"]
    uuid = payload["uuid"]
    user_service.block_access_token(jti)
    user_service.remove_all_refresh_tokens(uuid)
    return {"msg": "You have been logged out from all devices."}