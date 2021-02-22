# Reddit Clone

<hr/>

MVP
- users can create and account
- users can Login
- users can create a post
- users can delete a post
- users can update a post
- users can read all posts

ICEBOX
- post will apear from most to least upvotes
- users can up/down vote posts
- users can add/update/delete comments
- users can up'down vote comments

## DB

users

```SQL
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(45) NOT NULL,
    username VARCHAR(25) NOT NULL,
    password VARCHAR(5000) NOT NULL
);
```

posts
```SQL
CREATE TABLE posts (
    post_id SERIAL PRIMARY KEY,
    img_url TEXT,
    title VARCHAR(50),
    karma INT DEFAULT 0,
    user_id INT REFERENCES users(user_id),
);
```

## SERVER

- Dependencies:
    - massive
    - express
    - express-session
    - bcrypt
    - dotenv

- File Structure:
    - server/
      - index.js
      - controllers/
        - authController.js
        - postController.js

- Endpoints:
    - register => `/auth/register`
    - login => `/auth/login`
    - logout => `/auth/logout`
    - getUserSession => `/auth/get_user`
    - getPosts => `/api/posts`
    - deletePost => `/api/posts/:id`
    - editPost => `/api/posts/:id`
    - addPost => `/api/posts`

## FRONTEND

- Dependencies:
    - axios
    - redux
    - react-redux
    - redux-promise-middleware
    - react-router-dom
  
- File Structure
    - src/
        - App.js
        - reset.css
        - routes.js
        - redux/
            - store.js
            - userReducer.js
        - components/
            - Header.js
            - Auth.js
            - Form.js
            - Main.js
