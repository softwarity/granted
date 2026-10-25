package io.softwarity.granted.deployment;

import static io.restassured.RestAssured.given;

import java.io.StringReader;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

/** The OpenAPI document the application under test serves, read with JSON-P. Added to each test application. */
final class OpenApiDocument {

    private OpenApiDocument() {
    }

    static JsonObject document() {
        return Json.createReader(new StringReader(given().get("/q/openapi?format=json").then().statusCode(200).extract().asString()))
                .readObject();
    }

    static JsonObject operation(String path, String method) {
        return document().getJsonObject("paths").getJsonObject(path).getJsonObject(method);
    }

    static JsonValue json(String json) {
        return Json.createReader(new StringReader(json)).readValue();
    }
}
