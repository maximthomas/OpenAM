import { describe, it, expect } from 'vitest';
import { Constants } from '@/services/constants';

describe('constants', () => {
  it('has all required event constants', () => {
    expect(Constants.EVENT_REST_CALL_ERROR).toBe('common.delegate.EVENT_REST_CALL_ERROR');
    expect(Constants.EVENT_SHOW_LOGIN_DIALOG).toBe('dialog.EVENT_SHOW_LOGIN_DIALOG');
    expect(Constants.EVENT_THEME_CHANGED).toBe('main.EVENT_THEME_CHANGED');
    expect(Constants.EVENT_UNAUTHORIZED).toBe('view.EVENT_UNAUTHORIZED');
    expect(Constants.EVENT_LOGOUT).toBe('user.login.EVENT_LOGOUT');
  });

  it('has header param constants', () => {
    expect(Constants.HEADER_PARAM_PASSWORD).toBe('X-Password');
    expect(Constants.HEADER_PARAM_USERNAME).toBe('X-Username');
    expect(Constants.HEADER_PARAM_NO_SESSION).toBe('X-NoSession');
    expect(Constants.OPENAM_HEADER_PARAM_CUR_PASSWORD).toBe('currentpassword');
  });

  it('has default stylesheets', () => {
    expect(Constants.DEFAULT_STYLESHEETS).toHaveLength(2);
    expect(Constants.DEFAULT_STYLESHEETS[0]).toBe('css/bootstrap-3.3.5-custom.css');
    expect(Constants.DEFAULT_STYLESHEETS[1]).toBe('css/styles-admin.css');
  });

  it('has self service constants', () => {
    expect(Constants.SELF_SERVICE_FORGOTTEN_USERNAME).toBe('selfservice/forgottenUsername');
    expect(Constants.SELF_SERVICE_RESET_PASSWORD).toBe('selfservice/forgottenPassword');
    expect(Constants.SELF_SERVICE_REGISTER).toBe('selfservice/userRegistration');
  });

  it('has pattern constants', () => {
    expect(Constants.IPV4_PATTERN).toBeDefined();
    expect(Constants.IPV6_PATTERN).toBeDefined();
    expect(Constants.NUMBER_PATTERN).toBe('[-+]?[0-9]*[.,]?[0-9]+');
    expect(Constants.INTEGER_PATTERN).toBe('\\d+');
  });

  it('has anonymous credentials', () => {
    expect(Constants.ANONYMOUS_USERNAME).toBe('anonymous');
    expect(Constants.ANONYMOUS_PASSWORD).toBe('anonymous');
  });

  it('context is computed from current location', () => {
    expect(typeof Constants.context).toBe('string');
    expect(typeof Constants.CONSOLE_PATH).toBe('string');
    expect(Constants.CONSOLE_PATH).toContain('/console');
  });
});
