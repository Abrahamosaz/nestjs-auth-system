interface EmailOptions {
  to: string;
  subject: string;
  template: string; // this is the template name
  context?: any;
}
