import * as jwt from 'jsonwebtoken';

export const TEST_JWT_SECRET =
  process.env.JWT_SECRET || 'soc_test_secret_key_8f3a9e2c1b4d5e6f708192a3b4c5d6e7';
process.env.JWT_SECRET = TEST_JWT_SECRET;

export function getTestAuthHeader(): string {
  const token = jwt.sign(
    {
      sub: 'test-user-id',
      username: 'test_analyst',
      role: 'ADMIN',
      email: 'analyst@soc.platform.local',
    },
    TEST_JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '1h' },
  );
  return `Bearer ${token}`;
}
