/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016 ForgeRock AS.
 */

export interface SchemaProperty {
  type?: string;
  format?: string;
  enum?: unknown[];
  required?: boolean;
  properties?: Record<string, SchemaProperty>;
  title?: string;
  description?: string;
  propertyOrder?: number;
  [key: string]: unknown;
}

export function transformBooleanTypeToCheckboxFormat(property: SchemaProperty): void {
  if (property.type === "boolean") {
    property.format = "checkbox";
  }
}

export function transformEnumTypeToString(property: SchemaProperty): void {
  if (property.enum !== undefined) {
    property.type = "string";
  }
}

export function warnOnInferredPasswordWithoutFormat(property: SchemaProperty, name: string): void {
  const possiblePassword = name.toLowerCase().indexOf("password", name.length - 8) !== -1;
  const hasFormat = property.format === "password";
  if (property.type === "string" && possiblePassword && !hasFormat) {
    console.error(
      `[cleanJSONSchema] Detected (inferred) a password property "${name}" ` +
        'without format attribute of "password"'
    );
  }
}

export type SchemaTransform = (property: SchemaProperty, key: string) => void;

export const defaultTransforms: SchemaTransform[] = [
  transformBooleanTypeToCheckboxFormat,
  transformEnumTypeToString,
  warnOnInferredPasswordWithoutFormat,
];
