import { maskPhone, normalizePhone } from './phone';

describe('phone normalization', () => {
  it.each([
    ['+14155552671', '+14155552671'],
    ['+1 (415) 555-2671', '+14155552671'],
    ['+442079460018', '+442079460018'],
  ])('normalizes valid input', (input, e164) => expect(normalizePhone(input)).toEqual({ e164 }));

  it.each(['4155552671', 'abc', '😀', '+999999999999999999999999', ''])(
    'rejects invalid input',
    (input) => {
      expect(normalizePhone(input)).toBeNull();
    },
  );

  it('masks without exposing the middle digits', () =>
    expect(maskPhone('+989123456789')).toBe('+98********89'));
});
