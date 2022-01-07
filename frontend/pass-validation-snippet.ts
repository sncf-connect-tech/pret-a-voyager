private async handlePassCalls(type: string, content: string): Promise<void> {
    const encPassData = await this.encryptionSvc.encryptMessage(content);
    const dv: DossierVoyageur = this.dvService.getCurrentDV();
    const voyage: Voyage = this.storageService.getItem(storageKeys.journey);
    const ticket: Ticket = this.storageService.getItem(storageKeys.ticket);
    const healthPassRequest: HealthPassRequest = {
        reference: dv.reference,
        name: ticket.lastname,
        ticketId: ticket.id,
        passType: type,
        passContent: encPassData.iv + encPassData.ciphertext,
        publicKey: encPassData.key
    }
    this.subscription = this.hpService.postHealthPass(healthPassRequest).subscribe({
        next: () => {
            this.router.navigate(['/scan-success'])
        },
        error: (httpErr) => {
            this.router.navigate(['/scan-error'], { state: { error: httpErr.error } })
        }
    })
}