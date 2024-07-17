# NoSQL injection example

What happens if we come across a MongoDB (NoSQL) database where data we send is automatically treated as part of the query? This situation could allow us to manipulate the authentication query, potentially resulting in a complete bypass!

In a hypothetical scenario, a request searching for a valid account would utilize the find function, which accepts the following parameters:

```
auth_db.find( {
"user": "admin",
"password":"wrong_pass"
} )
```

In the first query, injecting a double quote (`"`) into the password field **(`"password":"wro"ng_pass"`)** causes the **find()** function to receive malformed data, triggering an exception due to syntax errors

Moving beyond simple quote injections, we can construct a payload that always evaluates to true. By adding an "OR" condition in the query, we specify that the password should be longer than or equal to an empty string:

```
auth_db.find( {
    "user": "admin",
    "password":"", "password":{"$gte":""}
} )
```

This query instructs MongoDB to find an account named "admin" with either a null password or any password data. As long as an account named "admin" exists, this condition will always return true, allowing unauthorized access.

In other words, the second query introduces a more sophisticated injection technique by leveraging MongoDB's query syntax.

By setting the password field to an empty string (`""`) and adding an **$gte** (greater than or equal) condition on the password **(`"password":{"$gte":""}`)**, we create a query that MongoDB interprets as finding an account where the password is either null or contains any data (`$gte` empty string).

This condition is designed to always evaluate to true, effectively bypassing authentication checks.

The payload is injected into the password field to exploit this vulnerability and gain unauthorized access.

## Reminder: basic MongoDB Syntax Guide

MongoDB is a NoSQL database that stores data in flexible, JSON-like documents. Understanding its syntax is essential for interacting with and querying data effectively.

**1. Connecting to MongoDB**

To connect to MongoDB from the command line using the mongo shell:

```
mongo
```

To connect to a specific database hosted on a server:

```
mongo <host>:<port>/<database_name> -u <username> -p <password>
```

**2. Basic Operations**

To insert a document into a collection:

```
db.collection_name.insertOne({ key: value });
```

To find documents in a collection:

```
db.collection_name.find({ key: value });
```

To update a document in a collection:

```
db.collection_name.updateOne({ key: value }, { $set: { new_key: new_value } });
```

To delete a document from a collection:

```
db.collection_name.deleteOne({ key: value });
```

**3. Query Operators**

MongoDB provides various query operators to filter and manipulate data:

Comparison Operators: $eq, $ne, $gt, $lt, $gte, $lte

Logical Operators: $and, $or, $not, $nor

Element Operators: $exists, $type

Array Operators: $in, $nin, $all, $elemMatch

The $in operator selects documents where the value of a field equals any value in the specified array. It's useful for querying documents where a field matches any of the given criteria.

Example:

```
// Find documents where the field "tags" contains any of the specified values
db.products.find({ tags: { $in: ["electronics", "gadgets"] } });
```

The $nin operator selects documents where the value of a field does not match any value in the specified array. It's the negation of $in.

Example:

```
// Find documents where the field "category" does not match any of the specified values
db.products.find({ category: { $nin: ["clothing", "shoes"] } });
```

The $all operator selects documents where the value of a field contains all elements in the specified array. It's useful for querying documents that contain all specified elements in an array field.

Example:

```
// Find documents where the field "features" contains all of the specified values
db.products.find({ features: { $all: ["waterproof", "durable"] } });
```

The $elemMatch operator selects documents where at least one element in the array matches all the specified criteria. It's used to query arrays that contain embedded documents or complex structures.

Example:

```
// Find documents where the array "orders" contains at least one element with both "product" and "quantity" fields matching the specified criteria
db.customers.find({ orders: { $elemMatch: { product: "laptop", quantity: { $gte: 2 } } } });
```

**4. Indexing**

Creating indexes can improve query performance:

```
db.collection_name.createIndex({ key: 1 });
```

**5. Aggregation**

Aggregation pipelines allow for complex data transformations:

```
db.collection_name.aggregate([
  { $match: { key: value } },
  { $group: { _id: "$key", count: { $sum: 1 } } }
]);
```

MongoDB's Aggregation Framework is a powerful tool used for processing and transforming data in a collection. It operates through an aggregation pipeline, which consists of multiple stages that process documents sequentially. Each stage transforms the documents as they pass through the pipeline.

Key Concepts and Operators:

**$match**

The $match stage filters documents based on specified criteria, similar to a query. It limits the documents passed to the next stage.

Example:

```
db.orders.aggregate([
  { $match: { status: "shipped" } }
]);
```

**$group**

The $group stage groups documents by a specified field and performs aggregation operations like sum, average, count, etc.

Example:

```
db.orders.aggregate([
  { $group: { _id: "$customerId", totalAmount: { $sum: "$amount" } } }
]);
```

**$sort**

The $sort stage sorts documents based on specified fields. Sort order is specified as 1 for ascending and -1 for descending.

Example:

```
db.orders.aggregate([
  { $sort: { orderDate: -1 } }
]);
```

**$project**

The $project stage reshapes documents by including, excluding, or adding new fields.

Example:

```
db.orders.aggregate([
  { $project: { orderId: 1, customerId: 1, orderDate: 1, year: { $year: "$orderDate" } } }
]);
```

**$limit**

The $limit stage restricts the number of documents passed to the next stage.

Example:

```
db.orders.aggregate([
  { $limit: 10 }
]);
```

**$skip**

The $skip stage skips a specified number of documents before passing the remaining documents to the next stage.

Example:

```
db.orders.aggregate([
  { $skip: 5 }
]);
```

**$unwind**

The $unwind stage deconstructs an array field from the input documents to output a document for each element of the array.

Example:

```
db.orders.aggregate([
  { $unwind: "$items" }
]);
```

$lookup

The $lookup stage performs a left outer join to another collection in the same database to filter in documents from the “joined” collection for processing.

Example:

```
db.orders.aggregate([
  {
    $lookup: {
      from: "customers",
      localField: "customerId",
      foreignField: "customerId",
      as: "customerDetails"
    }
  }
]);
```

**$addFields**

The $addFields stage adds new fields to documents. Fields added can include computed fields or fields based on existing data.

Example:

```
db.orders.aggregate([
  { $addFields: { totalWithTax: { $multiply: ["$total", 1.1] } } }
]);
```

**An example of a more complex aggregation pipeline that combines multiple stages:**

```
db.orders.aggregate([
  // Match orders shipped in the last month
  { $match: { status: "shipped", shipDate: { $gte: new Date("2023-06-01"), $lt: new Date("2023-07-01") } } },
  // Group by customer ID and calculate total order amount
  { $group: { _id: "$customerId", totalAmount: { $sum: "$amount" }, orders: { $push: "$$ROOT" } } },
  // Sort customers by total order amount in descending order
  { $sort: { totalAmount: -1 } },
  // Limit to top 5 customers
  { $limit: 5 },
  // Lookup customer details from the customers collection
  {
    $lookup: {
      from: "customers",
      localField: "_id",
      foreignField: "customerId",
      as: "customerDetails"
    }
  },
  // Project the necessary fields
  { $project: { customerId: "$_id", totalAmount: 1, customerDetails: { $arrayElemAt: ["$customerDetails", 0] }, orders: 1 } }
]);
```
In this example, the pipeline:

- Filters orders to include only those shipped in the last month.

- Groups the orders by customer ID, calculating the total amount for each customer.

- Sorts the customers by total order amount in descending order.

- Limits the results to the top 5 customers.

- Joins with the customers collection to retrieve customer details.
   
- Projects the necessary fields, including customer details and order information.

**6. Text Search**

Performing text search queries on indexed fields:

```
db.collection_name.find({ $text: { $search: "keyword" } });
```

**7. Sorting and Limiting Results**

Sorting results based on a field and limiting the number of returned documents:

```
db.collection_name.find().sort({ key: 1 }).limit(10);
```
