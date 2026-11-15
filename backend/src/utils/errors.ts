// Simple error class: throw new AppError(400, "message") anywhere in a route.
export class AppError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}
