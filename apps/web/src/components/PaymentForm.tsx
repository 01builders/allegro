import { useState } from "react";
import { useAccount } from "wagmi";
import { Hooks } from "wagmi/tempo";
import { isAddress, parseUnits, pad, stringToHex } from "viem";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TOKENS, alphaUsd } from "@/lib/wagmi.config";

type TokenAddress = (typeof TOKENS)[number]["address"];

export function PaymentForm({
  onTxHash,
}: {
  onTxHash: (hash: string) => void;
}) {
  const { address, isConnected } = useAccount();
  const [recipient, setRecipient] = useState("");
  const [selectedToken, setSelectedToken] = useState<TokenAddress>(alphaUsd);
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("");
  const [error, setError] = useState<string | null>(null);

  const metadata = Hooks.token.useGetMetadata({ token: selectedToken });
  const balance = Hooks.token.useGetBalance({
    account: address,
    token: selectedToken,
  });
  const transfer = Hooks.token.useTransferSync();

  const decimals = metadata.data?.decimals ?? 6;
  const symbol = metadata.data?.symbol ?? "???";
  const balanceFormatted =
    balance.data !== undefined
      ? (Number(balance.data) / 10 ** decimals).toFixed(decimals)
      : "...";

  const recipientValid = recipient !== "" && isAddress(recipient);
  const amountValid = amount !== "" && Number(amount) > 0;
  const canSubmit = isConnected && recipientValid && amountValid && !transfer.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!canSubmit) return;

    const parsedAmount = parseUnits(amount, decimals);
    const memoHex =
      memo.trim() !== ""
        ? pad(stringToHex(memo.trim()), { size: 32 })
        : undefined;

    // nonceKey triggers viem's Tempo-native tx (type 0x76) instead of legacy EVM.
    // uint192 max is 24 bytes; upper 8 bytes of this 32-byte value will be truncated.
    const FASTPAY_NONCE_KEY = BigInt("0x" + "5b".repeat(24));

    transfer.mutate(
      {
        amount: parsedAmount,
        to: recipient as `0x${string}`,
        token: selectedToken,
        nonceKey: FASTPAY_NONCE_KEY,
        ...(memoHex !== undefined ? { memo: memoHex } : {}),
      },
      {
        onSuccess(data) {
          if (typeof data === "string") {
            onTxHash(data);
          }
          setAmount("");
          setMemo("");
        },
        onError(err) {
          setError(err.message);
        },
      },
    );
  };

  if (!isConnected) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Send Payment</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Connect your wallet to send a payment.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Send Payment</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label>From</Label>
            <Input value={address ?? ""} disabled className="font-mono" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="recipient">To</Label>
            <Input
              id="recipient"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="0x..."
              className="font-mono"
            />
            {recipient !== "" && !recipientValid && (
              <p className="text-xs text-destructive">Invalid address</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="token">Token</Label>
            <Select
              value={selectedToken}
              onValueChange={(v) => setSelectedToken(v as TokenAddress)}
            >
              <SelectTrigger id="token">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TOKENS.map((t) => (
                  <SelectItem key={t.address} value={t.address}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Balance: {balanceFormatted} {symbol}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="amount">Amount</Label>
            <Input
              id="amount"
              type="number"
              min={0}
              step="any"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0.00"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="memo">Memo (optional)</Label>
            <Input
              id="memo"
              value={memo}
              onChange={(e) => setMemo(e.target.value)}
              placeholder="Payment for..."
              maxLength={32}
            />
          </div>

          <Button type="submit" className="w-full" disabled={!canSubmit}>
            {transfer.isPending ? "Sending..." : "Send"}
          </Button>

          {error && <p className="text-sm text-destructive">{error}</p>}
          {transfer.isError && !error && (
            <p className="text-sm text-destructive">
              {transfer.error.message}
            </p>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
