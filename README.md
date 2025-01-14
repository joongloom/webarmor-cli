
# WebArmor 

**WebArmor** - легковесный сканер уязвимостей веб-приложений. Позволяет быстро провести аудит безопасности и проверки базовых настроек защищенности сайтов через терминал.

## Реализованные проверки

- **SQL Injection (SQLi)**
- **Cross-Site Scripting (XSS)**
- **Local File Inclusion (LFI)**
- **SSL/TLS (наличие HTTPS)**
- **Безопасность заголовков (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)**
- **Флаги Cookies (Secure, HttpOnly)**
- **Наличие CSRF-токенов в формах**

## Стек

- **Python 3.x**
- **Requests**
- **BeautifulSoup4**
- **Rich**

## Установка

1. Скопируйте репозиторий

	```
	git clone https://github.com/joongloom/webarmor-cli.git
	```

2. Установите необходимые зависимости:

   ```
      pip install -r requirements.txt 
    ```

## Использование

Для запуска сканирования просто укажите URL целевого ресурса:

```
python main.py https://google.com
```

