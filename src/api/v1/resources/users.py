from jose import jwt, JWTError

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from starlette.status import HTTP_403_FORBIDDEN

from src.api.v1.schemas import UserCreate, UserModel, Token, UserLogin
from src.services.user import UserService, get_user_service

from src.core.config import JWT_SECRET_KEY, JWT_EXPIRATION, JWT_ALGORITHM


router = APIRouter()
reasable_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

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

    refresh_token = user_service.create_refresh_token(user_uuid)
    refresh_uuid = user_service.get_uuid(refresh_token)
    access_token = user_service.create_access_token(user_data, refresh_uuid)

    user_service.add_refresh_token(refresh_token)
    return Token(**{"access_token": access_token, "refresh_token": refresh_token})


@router.post(
    path="/refresh",
    response_model=Token,
    summary="Обновляет токен",
    tags=["users"],
)
def refresh(user_service: UserService = Depends(get_user_service),
            token: str = Depends(reasable_oauth2)) -> Token:
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

    refresh_token = user_service.create_refresh_token(user_uuid=user_uuid)
    refresh_uuid = user_service.get_uuid(refresh_token)
    access_token = user_service.create_access_token(user_data, refresh_uuid)

    return Token(**{"access_token": access_token, "refresh_token": refresh_token})


@router.get(
    path="/users/me",
    summary="Смотреть свой профиль",
    tags=["users"],
)
def get_user_info(user_service: UserService = Depends(get_user_service),
                  token: str = Depends(reasable_oauth2)):
    current_user = user_service.get_user_by_token(token)
    return {"user": UserModel(**current_user)}


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
