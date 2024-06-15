-- CreateTable
CREATE TABLE "refreshtokens" (
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expireTime" TIMESTAMP(3) NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "refreshtokens_token_key" ON "refreshtokens"("token");
