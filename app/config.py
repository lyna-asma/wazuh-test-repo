from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    wazuh_base_url: str
    wazuh_user: str
    wazuh_pass: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()