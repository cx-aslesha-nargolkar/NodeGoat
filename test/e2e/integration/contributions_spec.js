/// <reference types="Cypress" />

describe("/contributions behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  it("Should redirect if the user has not logged in", () => {
    cy.visitPage("/contributions");
    cy.url().should("include", "login");
  });

  it("Should be accesible for a logged user", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.url().should("include", "contributions");
  });

  it("Should be a table with several inputs", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .should("have.length", 3);
  });

  it("Should input be modified", () => {
    const value = "12";
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .first()
      .clear()
      .type(value);

    cy.get("button[type='submit']")
      .click();

    cy.get("tbody > tr > td")
      .eq(1)
      .contains(`${value} %`);

    cy.get(".alert-success")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });

  // Security regression tests: CWE-94 Code Injection via eval() — fixed by using parseInt()
  // These tests verify that user-supplied non-numeric (potentially malicious) strings are
  // rejected and do NOT execute arbitrary code on the server.

  it("Should reject a JavaScript expression injected in the roth field (code injection attempt)", () => {
    // An attacker might try to inject a JS expression such as "1+1" or "process.exit(1)".
    // With eval() this would execute; with parseInt() it returns NaN and triggers validation.
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("5");
    inputs.eq(1).clear().type("5");
    // Inject a JS expression into the roth field
    inputs.eq(2).clear().type("1+1");

    cy.get("button[type='submit']").click();

    // The server should return a validation error, not accept the expression
    cy.get(".alert-danger, .alert-error, [class*='error']")
      .should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should reject a string payload in the preTax field (code injection attempt)", () => {
    // A string like "process.env" or any non-numeric value must be rejected.
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("process.env");
    inputs.eq(1).clear().type("5");
    inputs.eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .alert-error, [class*='error']")
      .should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should reject negative numbers to prevent bypass of contribution limits", () => {
    // Negative values should be rejected by server-side validation.
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("-5");
    inputs.eq(1).clear().type("5");
    inputs.eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .alert-error, [class*='error']")
      .should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should reject contributions that exceed 30 percent in total", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("20");
    inputs.eq(1).clear().type("10");
    inputs.eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .alert-error, [class*='error']")
      .should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should accept valid numeric contributions that total 30 percent or less", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("10");
    inputs.eq(1).clear().type("10");
    inputs.eq(2).clear().type("10");

    cy.get("button[type='submit']").click();

    cy.get(".alert-success").should("be.visible");
    cy.url().should("include", "contributions");
  });
});
