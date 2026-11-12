module access_control (
    input wire clk,
    input wire rst_n,

    input wire req,
    input wire write_en,
    input wire privilege,

    input wire [7:0] address,

    output reg grant,
    output reg security_alert,

    output reg [15:0] violation_count
);

    wire protected_region;

    assign protected_region = (address >= 8'h80);

    always @(posedge clk or negedge rst_n)
    begin

        if (!rst_n)
        begin
            grant <= 1'b0;
            security_alert <= 1'b0;
            violation_count <= 16'd0;
        end

        else
        begin
            grant <= 1'b0;
            security_alert <= 1'b0;

            if (req)
            begin

                if (protected_region)
                begin

                    if (privilege && !write_en)
                    begin
                        grant <= 1'b1;
                    end

                    else
                    begin
                        grant <= 1'b0;
                        security_alert <= 1'b1;

                        if (violation_count < 16'hFFFF)
                        begin
                            violation_count <=
                                violation_count + 1'b1;
                        end
                    end

                end

                else
                begin
                    grant <= 1'b1;
                end

            end

        end

    end

endmodule