import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import {Router} from '@angular/router';
import {Message, MessageService} from 'primeng/api';
import {AuthService} from 'src/app/zynerator/security/shared/service/Auth.service';
import {LayoutService} from 'src/app/layout/service/app.layout.service';



@Component({
  selector: 'app-change-password-admin',
  templateUrl: './change-password-admin.component.html',
  styleUrls: ['./change-password-admin.component.css']
})
export class ChangePasswordAdminComponent implements OnInit {
  successMessage: string = '';
    errorMessage: string = '';
    passwordChange = new FormGroup({
        email: new FormControl('',Validators.required),
        password: new FormControl('',Validators.required),
        confermpassword: new FormControl('',Validators.required)
    });

    messages: Message[] = [];
    active : boolean=false;

    constructor(private authService: AuthService,public layoutService: LayoutService, private router: Router,private messageService: MessageService) { }

    ngOnInit(): void {
        this.messages = [];
    }

    submit() {
        const formValues = this.passwordChange.value;
        const email = formValues.email;
        const password = formValues.password;
        this.authService.forgetPassword(email, password).then(
            (response: any) => {
                if (response && response.message) {
                    this.successMessage = response.message;
                    this.errorMessage = '';
                    this.messageService.add({
                        severity: 'success',
                        summary: 'Success',
                        detail: response.message + ' *** Check your email to activate your account ***'
                    });
                    setTimeout(() => {
                        this.clearMessages();
                    }, 60000);

                } else {
                    this.errorMessage = 'Error occured';
                    this.successMessage = '';
                }
            },
            (error: any) => {
                if (error && error.error && error.error.message) {
                    this.errorMessage = error.error.message;
                    this.successMessage = '';
                } else {
                    this.errorMessage = 'Une erreur inattendue est survenue2';
                    this.successMessage = '';
                }
            }
        );
    }

    clearMessages() {
        this.messageService.clear();
    }


}
