export function storeToken(token: string) {
  // Insecure token storage - should be caught
  localStorage.setItem("token", token);
}
