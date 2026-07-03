/**
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
 * Copyright 2026 3A Systems LLC.
 */

import { describe, expect, it } from 'vitest'
import { getMessageType, getScript, isScriptTextOutputCallback } from './callbacks.ts'
import type { AmCallback } from './types.ts'

function textOutputCallback(messageType: AmCallback['output'][number]['value'], message = ''): AmCallback {
  return {
    type: 'TextOutputCallback',
    output: [
      { name: 'message', value: message },
      { name: 'messageType', value: messageType },
    ],
    input: [],
  }
}

describe('getMessageType', () => {
  it('reads a numeric messageType (mock fixtures model it this way)', () => {
    expect(getMessageType(textOutputCallback(4))).toBe(4)
  })

  it('reads a string messageType — the real AM wire format (String.valueOf(messageType))', () => {
    expect(getMessageType(textOutputCallback('4'))).toBe(4)
  })

  it('defaults to 0 when messageType is missing or non-numeric', () => {
    expect(getMessageType({ type: 'TextOutputCallback', output: [], input: [] })).toBe(0)
    expect(getMessageType(textOutputCallback('not-a-number'))).toBe(0)
  })
})

describe('isScriptTextOutputCallback', () => {
  it('is true for a TextOutputCallback with messageType 4 (string, the real wire format)', () => {
    expect(isScriptTextOutputCallback(textOutputCallback('4'))).toBe(true)
  })

  it('is true for a TextOutputCallback with messageType 4 (number, as mock fixtures model it)', () => {
    expect(isScriptTextOutputCallback(textOutputCallback(4))).toBe(true)
  })

  it('is false for other messageType values', () => {
    expect(isScriptTextOutputCallback(textOutputCallback(0))).toBe(false)
    expect(isScriptTextOutputCallback(textOutputCallback(1))).toBe(false)
    expect(isScriptTextOutputCallback(textOutputCallback(2))).toBe(false)
  })

  it('is false for a non-TextOutputCallback', () => {
    expect(isScriptTextOutputCallback({ type: 'PasswordCallback', output: [], input: [] })).toBe(false)
  })
})

describe('getScript', () => {
  it("returns the callback's message output (the raw script)", () => {
    expect(getScript(textOutputCallback('4', "setResult('x');"))).toBe("setResult('x');")
  })

  it('returns an empty string when there is no message output', () => {
    expect(getScript({ type: 'TextOutputCallback', output: [], input: [] })).toBe('')
  })
})
