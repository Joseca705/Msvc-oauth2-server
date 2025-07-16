# Neighborhood Store Project

This project is designed to manage the flow of products within the store. With this system, it is possible to purchase products and store them in stock, sell the products available in the stock, search for products by their code, and even have a kardex where you can check the most sold products, products that are below a predefined threshold, and view the profit made over a date range.

## Installation
To install and use this system, Docker and Docker Compose must be installed. Use the following command to start the system:
```batch=
$ docker-compose up
```
The creation of the database and its seeders is done automatically by the microservice named: `msvc-users`, which includes the dependency Flyway for performing migrations.

## Flows
To understand the flow, requests intended to be used with Postman are highlighted in bold.

### Flow for product creation
This flow starts by sending only the necessary data for its creation **(1. Store - Register a new product)**.

### Flow for adding new batches
This flow starts by listing the available products **(1.2 List of products)** and the available suppliers **(1.3 List of suppliers)**. Once the product and supplier details (with their respective IDs) are obtained, the next step is to create a new batch by submitting the corresponding data **(2. Store - Save batch)**. Once the batch is created, we proceed to register this OUTPUT movement in the kardex, which is handled internally.

### Flow for registering a new sale
This flow starts by retrieving a product's information using its code **(1.1 Search product by code)**. This process is repeated until the client has provided all the products to be purchased. After obtaining all the products, we create an array with the information of all the items and proceed to register the sale **(3. Make sale)**. Once the sale is registered, we record the INPUTs in the kardex, which is handled internally.

### Flow to get the top-selling products
To retrieve this information, simply make a request to **(4. Kardex - Get most sold products)**, where the only required parameter is the limit.

### Flow to get products below their set threshold
To retrieve this information, simply make a request to **(5. Kardex - Get products below threshold)**.

### Flow to get profit within a date range
To retrieve this information, simply make a request to **(6. Kardex - Get profits)**, where the parameters are the start date and end date.

### Flow to update product information
This flow is the same as the **Flow for product creation**, but the method changes to **(5.1 Update Price or Threshold of a product)**.

## Integration Testing
To run integration tests, you need to have Postman installed and import the file **Integration Tests of the Microservice.postman_collection.json**, which includes the corresponding documentation.

## Conclusions
The product meets the given requirements, but it can still be more scalable if additional features are added, such as discounts for frequent customers, online shopping, shopping carts, favorites, and discounted products.
